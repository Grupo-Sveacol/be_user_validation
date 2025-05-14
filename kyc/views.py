import json
import hmac
import hashlib
from django.conf import settings
from django.http import HttpResponseRedirect, JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render, get_object_or_404
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny
from datetime import datetime, timedelta
from .serializers import SessionDetailsSerializer
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.models import User
import requests
from .utils.tusdatos_client import get_background_check
from .serializers import SessionDetailsSerializer
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.models import User
from rest_framework.decorators import api_view, permission_classes

from .models import UserDetails, SessionDetails
from .utils.didit_client import create_session, retrieve_session


def kyc_test(request):
    # Lee el token desde el archivo .env (a través de settings)
    token = settings.JWT_TOKEN
    print("JWT_TOKEN:", token)
    context = {
        "jwt_token": settings.JWT_TOKEN  # Este es el token constante definido en tu .env
    }
    return render(request, "kyc/test.html", context)

class DiditKYCAPIView(APIView):
    """
    POST /kyc/api/kyc/
    Creates a new KYC session in Didit and stores it locally.
    """
    def post(self, request):
        data = request.data
        print("🔹 Received data:", data)

        # Validar campos obligatorios
        if not data.get("first_name") or not data.get("last_name") or not data.get("document_id"):
            return Response(
                {"error": "Missing fields 'first_name', 'last_name', or 'document_id'."},
                status=status.HTTP_400_BAD_REQUEST
            )

        document_id = data["document_id"]

        # Si ya existe un UserDetails con ese document_id, retornar error
        if UserDetails.objects.filter(document_id=document_id).exists():
            return Response(
                {"error": "Ese usuario ya está registrado"},
                status=status.HTTP_409_CONFLICT
            )

        # Registrar personal data localmente
        personal_data = UserDetails.objects.create(
            first_name=data["first_name"],
            last_name=data["last_name"],
            document_id=document_id
        )

        # Registrar session details localmente
        session_details = SessionDetails.objects.create(
            personal_data=personal_data,
            status="pending"
        )

        
        # Parameters for Didit
        features = data.get("features", "OCR")
        vendor_data = data.get("vendor_data", data["document_id"])
        callback_url = f"{settings.FRONTEND_URL}/user-validation/{vendor_data}"

        print("🔹 Callback URL:", callback_url)

        try:
            session_data = create_session(features, callback_url, vendor_data)
            print("🔹 create_session response:", session_data)

            session_details.session_id = session_data["session_id"]
            session_details.verification_url = session_data["url"]
            session_details.save()

            response_data = {
                "message":          "KYC session created successfully",
                "session_id":       session_data["session_id"],
                "verification_url": session_data["url"],
                "expires_at":       session_data.get(
                                         "expires_at",
                                         (datetime.now() + timedelta(days=7)).isoformat()
                                     )
            }
            return Response(response_data, status=status.HTTP_201_CREATED)

        except Exception as e:
            print("❌ Error in DiditKYCAPIView:", str(e))
            # Limpiar solo lo creado en este request
            session_details.delete()
            personal_data.delete()
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
@csrf_exempt
def didit_webhook(request):
    """
    POST /kyc/api/webhook/
    Endpoint to receive status updates from Didit.
    """
    print("✅ Webhook received!")
    print(f"Method: {request.method}")
    print(f"Request: {request}")

    # Para solicitudes POST, procesar el JSON como antes
    if request.method == "POST":
        try:
            print(f"Received data: {request.body.decode('utf-8')}")
            data = json.loads(request.body)
            
            # Extract main data
            session_id = data.get("session_id") or data.get("id")
            didit_status = data.get("status")

            if not session_id or not didit_status:
                return JsonResponse({"error": "Incomplete data (session_id/id, status)"}, status=400)

            session_details = get_object_or_404(SessionDetails, session_id=session_id)
                
            # Update the status
            session_details.status = didit_status.lower()
            
            # If the status is "completed", get the complete decision
            if didit_status.upper() == "COMPLETED":
                try:
                    decision_data = retrieve_session(session_id)
                    print(f"✅ Decision data retrieved for session {session_id}")
                except Exception as e:
                    print(f"⚠️ Error retrieving complete decision: {str(e)}")
                    # Don't fail the webhook if this fails
            
            session_details.save()
            print(f"✅ Webhook processed: Session {session_id}, Status: {didit_status}")

            return JsonResponse({
                "message": "Webhook processed", 
                "status": didit_status,
                "session_id": session_id
            })
        except Exception as e:
            print(f"❌ Error processing webhook: {str(e)}")
            return JsonResponse({"error": str(e)}, status=500)
    else:
        return JsonResponse({"error": "Method not allowed"}, status=405)

class RetrieveSessionAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, document_id):
        try:
            session_details = get_object_or_404(
                SessionDetails,
                personal_data__document_id=document_id
            )
            session_id = session_details.session_id
            data = retrieve_session(session_id)
            return Response(
                {"session_id": session_id, "data": data},
                status=status.HTTP_200_OK
            )
        except Exception as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class GetServiceToken(APIView):
    permission_classes = [AllowAny]
    def get(self, request):

        # Create or get service account
        user, created = User.objects.get_or_create(
            username='service_account',
            defaults={'is_active': True}
        )
        
        refresh = RefreshToken.for_user(user)
        
        # Return the token with timestamp
        return Response({
            'access': str(refresh.access_token),
            'refresh': str(refresh),
        })
    
class ResolveSessionAPIView(APIView):
    """
    DELETE /kyc/api/session/<session_id>/resolve/
    Resolve a session 
    """

    def delete(self, request, session_id):
        try:
            # Find the session
            session = get_object_or_404(SessionDetails, session_id=session_id)
            
            # Get reference to the personal data before we modify anything
            user_details = session.personal_data
            
            # Update session status to rejected
            session.status = "rejected"
            session.save()
            
            # Delete the user's personal data
            if user_details:
                user_details.delete()
                
            return Response({
                "message": "Session rejected and user data deleted successfully",
                "session_id": session_id
            }, status=status.HTTP_200_OK)
            
        except SessionDetails.DoesNotExist:
            return Response({
                "error": f"Session with ID {session_id} not found"
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            print(f"❌ Error rejecting session: {str(e)}")
            return Response({
                "error": f"Failed to reject session: {str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def patch(self, request, session_id):
        try:
            didit_session = retrieve_session(session_id)
            session_details = get_object_or_404(SessionDetails, session_id=session_id)
            kyc_data = didit_session.get("kyc", {})
            print(f"🔹 KYC data: {kyc_data}")

            if not kyc_data:
                print("❌ No KYC data found")
                return Response({"error": "No KYC data found in session"}, status=status.HTTP_400_BAD_REQUEST)

            document_id = kyc_data.get("personal_number") or kyc_data.get("document_number")
            first_name = kyc_data.get("first_name", "Unknown")
            last_name = kyc_data.get("last_name", "")
            document_type = kyc_data.get("document_type", "unknown")
            date_of_birth = kyc_data.get("date_of_birth")
            nationality = kyc_data.get("issuing_state_name")

            print(f"Document ID: {document_id}, First Name: {first_name}, Last Name: {last_name}")

            if not session_details.personal_data:
                if not document_id:
                    print("❌ Missing document ID in KYC data")
                    return Response({"error": "Missing document ID in KYC data"}, status=status.HTTP_400_BAD_REQUEST)
                user_details = UserDetails.objects.create(
                    first_name=first_name,
                    last_name=last_name,
                    document_id=document_id,
                    document_type=document_type,
                    date_of_birth=date_of_birth,
                    nationality=nationality
                )
                print(f"Created UserDetails: {user_details.id}")
                session_details.personal_data = user_details
                session_details.save()
                print(f"Linked UserDetails to SessionDetails: {session_details.id}")
            else:
                user_details = session_details.personal_data
                if document_id:
                    user_details.document_id = document_id
                if document_type:
                    user_details.document_type = document_type
                if first_name:
                    user_details.first_name = first_name
                if last_name:
                    user_details.last_name = last_name
                if date_of_birth:
                    user_details.date_of_birth = date_of_birth
                if nationality:
                    user_details.nationality = nationality
                user_details.save()
                print(f"Updated UserDetails: {user_details.id}")

            status_from_didit = kyc_data.get("status") or didit_session.get("status")
            if status_from_didit:
                session_details.status = status_from_didit.lower()
                session_details.save()
                print(f"Updated SessionDetails status: {session_details.status}")

            serializer = SessionDetailsSerializer(session_details)
            return Response(serializer.data, status=status.HTTP_200_OK)

        except Exception as e:
            print(f"❌ Error updating session data: {str(e)}")
            print(traceback.format_exc())
            return Response(
                {"error": f"Failed to update session: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

            try:
                # Retrieve the session data from Didit
                didit_session = retrieve_session(session_id)
                # Get our local record
                session_details = get_object_or_404(SessionDetails, session_id=session_id)
                
                # Extract the KYC data from the session
                kyc_data = didit_session.get("kyc", {})
                print(f"🔹 KYC data: {kyc_data}")
                
                if not kyc_data:
                    return Response({"error": "No KYC data found in session"}, 
                                    status=status.HTTP_400_BAD_REQUEST)
                
                # Prepare the user details data
                document_id = kyc_data.get("personal_number") or kyc_data.get("document_number")
                first_name = kyc_data.get("first_name", "Unknown")
                last_name = kyc_data.get("last_name", "")
                document_type = kyc_data.get("document_type", "unknown")
                date_of_birth = kyc_data.get("date_of_birth")
                nationality = kyc_data.get("issuing_state_name")
                
                # Handle the case where there's no personal data
                if not session_details.personal_data:
                    # Create UserDetails with the required fields
                    if not document_id:
                        return Response({"error": "Missing document ID in KYC data"}, 
                                        status=status.HTTP_400_BAD_REQUEST)
                        
                    # Create with initial data
                    user_details = UserDetails.objects.create(
                        first_name=first_name,
                        last_name=last_name,
                        document_id=document_id,
                        document_type=document_type,
                        date_of_birth=date_of_birth,
                        nationality=nationality
                    )
                    
                    # Associate with session
                    session_details.personal_data = user_details
                    session_details.save()
                    
                    print(f"Created new UserDetails with ID {user_details.id} for session {session_id}")
                else:
                    # Update existing UserDetails
                    user_details = session_details.personal_data
                    
                    # Update fields if they exist in KYC data
                    if document_id:
                        user_details.document_id = document_id
                    if document_type:
                        user_details.document_type = document_type
                    if first_name:
                        user_details.first_name = first_name
                    if last_name:
                        user_details.last_name = last_name
                    if date_of_birth:
                        user_details.date_of_birth = date_of_birth
                    if nationality:
                        user_details.nationality = nationality
                        
                    # Save the updated user details
                    user_details.save()
                    print(f"Updated UserDetails with ID {user_details.id} for session {session_id}")
                
                # Update session status from Didit response
                status_from_didit = kyc_data.get("status") or didit_session.get("status")
                if status_from_didit:
                    session_details.status = status_from_didit.lower()
                    session_details.save()
                
                # Return updated session details
                serializer = SessionDetailsSerializer(session_details)
                return Response(serializer.data, status=status.HTTP_200_OK)
                
            except Exception as e:
                print(f"❌ Error updating session data: {str(e)}")
                return Response(
                    {"error": f"Failed to update session: {str(e)}"},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

class TusDatosAPIView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]

    def get(self, request, document_id: str):
        session = get_object_or_404(SessionDetails, personal_data__document_id=document_id)
        didit_data = retrieve_session(session.session_id)
        kyc_data = didit_data.get("kyc") or {}

        if not kyc_data:
            # 🔁 Mock si el usuario no ha iniciado sesión (kyc es null)
            mock_failure = {
            "estado": "Revisión necesaria",
            "resultados": [
                {
                "lista": "Antecedentes judiciales",
                "estado": "Coincidencia encontrada",
                "detalle": "Coincidencia parcial con cédula en base de datos judicial. Requiere validación."
                },
                {
                "lista": "Lavado de activos",
                "estado": "Sin registros"
                },
                {
                "lista": "Interpol",
                "estado": "Sin registros"
                }
            ],
            "detalle": "El ciudadano presenta coincidencias que requieren revisión manual antes de continuar con el proceso KYC.",
            "evaluacion_final": "Observado"
            }
            return Response({
                "document_number": document_id,
                "tusdatos": mock_failure
            }, status=status.HTTP_200_OK)

        # ✅ Si hay datos en kyc, construimos mock exitoso
        full_name = kyc_data.get("full_name")
        date_of_issue = kyc_data.get("date_of_issue")
        document_number = kyc_data.get("personal_number") or kyc_data.get("document_number")

        if not all([full_name, date_of_issue, document_number]):
            return Response({"error": "Faltan campos en Didit"}, status=status.HTTP_400_BAD_REQUEST)

        mock_success = {
            "estado": "Exitoso",
            "resultados": [
                {"lista": "Antecedentes judiciales", "estado": "Sin registros"},
                {"lista": "Lavado de activos", "estado": "Sin registros"}
            ],
            "detalle": "El ciudadano no presenta antecedentes."
        }

        return Response({
            "input": {
                "full_name": full_name,
                "date_of_issue": date_of_issue,
                "document_number": document_number
            },
            "tusdatos": mock_success
        }, status=status.HTTP_200_OK)

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
from datetime import datetime
from .models import UserDetails, SessionDetails

@api_view(['POST'])
@permission_classes([AllowAny])
def verificar_tusdatos(request):
    document_type = request.data.get("document_type")
    document_number = request.data.get("document_number")

    if not document_type or not document_number:
        return Response({"error": "Se requieren document_type y document_number"}, status=400)

    user = UserDetails.objects.filter(document_id=document_number).first()

    simulated_response = {
        "document_type": document_type,
        "document_number": document_number,
        "background_check": [
            {"list_name": "Lista de antecedentes judiciales", "status": "Sin registros"},
            {"list_name": "Lista de lavado de activos", "status": "Sin registros"}
        ],
        "verificado_por": "TusDatos (mock)",
        "timestamp": datetime.now().isoformat()
    }

    if user:
        return Response(simulated_response, status=200)

    return Response({"error": "Usuario no encontrado"}, status=404)
