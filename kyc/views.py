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





from .models import UserDetails, SessionDetails
from .utils.didit_client import create_session, retrieve_session, update_session_status


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
        
        if not data.get("first_name") or not data.get("last_name") or not data.get("document_id"):
            return Response({"error": "Missing fields 'first_name', 'last_name', or 'document_id'."},
                            status=status.HTTP_400_BAD_REQUEST)

        # Register personal data locally in the database
        personal_data = UserDetails.objects.create(
            first_name=data["first_name"],
            last_name=data["last_name"],
            document_id=data["document_id"]
        )

        # Register session details locally in the database
        session_details = SessionDetails.objects.create(
            personal_data=personal_data,
            status="pending"
        )

        
        # Parameters for Didit
        features = data.get("features", "OCR")
        callback_url = f"{settings.BACKEND_URL}/kyc/api/webhook/"
        vendor_data = data.get("vendor_data", data["document_id"])

        print("🔹 Callback URL:", callback_url)

        try:
            session_data = create_session(features, callback_url, vendor_data)
            print("🔹 create_session response:", session_data)
            
            # Update the record with all session data
            session_details.session_id = session_data["session_id"]
            session_details.save()

            # Create response
            response_data = {
                "message": "KYC session created successfully",
                "session_id": session_data["session_id"],
                "verification_url": session_data["url"]
            }
            
            # Add optional fields if available
            if "expires_at" in session_data:
                response_data["expires_at"] = session_data["expires_at"]
            else:
                response_data["expires_at"] = (datetime.now() + timedelta(days=7)).isoformat()
            
            return Response(response_data, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            print("❌ Error in DiditKYCAPIView:", str(e))
            personal_data.delete()
            session_details.delete()
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
    
    # Manejar solicitudes GET sin procesar JSON
    if request.method == "GET":
        return HttpResponseRedirect(f'{settings.FRONTEND_URL}/user-validation/')
       
    
    # Para solicitudes POST, procesar el JSON como antes
    elif request.method == "POST":
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
            
            # Save nationality, date of birth and document type if available
            kyc_data = data.get("decision", {}).get("kyc", {})
            print(f"🔹 KYC data: {kyc_data}")
            personal_data = session_details.personal_data
            personal_data.nationality = kyc_data.get("issuing_state_name")
            date_of_birth = kyc_data.get("date_of_birth")
            document_type = kyc_data.get("document_type")
            document_id = kyc_data.get("document_number")
            first_name = kyc_data.get("first_name")
            last_name = kyc_data.get("last_name")
            
            # In didit_webhook, use update_or_create instead of separate operations:
            personal_data_updates = {}
            if document_id:
                personal_data_updates['document_id'] = document_id
            if date_of_birth:
                personal_data_updates['date_of_birth'] = date_of_birth
            if document_type:
                personal_data_updates['document_type'] = document_type
            if first_name:
                personal_data_updates['first_name'] = first_name
            if last_name:
                personal_data_updates['last_name'] = last_name
                
            
            # Add nationality if it exists
            if kyc_data.get("issuing_state_name"):
                personal_data_updates['nationality'] = kyc_data.get("issuing_state_name")

            if personal_data_updates:
                UserDetails.objects.filter(id=session_details.personal_data.id).update(**personal_data_updates)
                # Refresh the instance from the database
                personal_data.refresh_from_db()
            
            personal_data.save()
            
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

    def get(self, request, session_id):
        try:
            data = retrieve_session(session_id)
            return Response(data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UpdateStatusAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def patch(self, request, session_id):
        print("Request body:", request.data)
        
        new_status = request.data.get("new_status")
        if not new_status:
            return Response({"error": "Missing 'status' in request"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            updated_data = update_session_status(session_id, new_status)
            return Response(updated_data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class SessionDetailView(APIView):
    """
    GET /api/session/<id>/
    Retrieves a specific session detail by its ID.
    """
    
    def get(self, request, id):
        session = get_object_or_404(SessionDetails, session_id=id)
        serializer = SessionDetailsSerializer(session)
        print(serializer.data)
        return Response(serializer.data)
    
    

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
    
  