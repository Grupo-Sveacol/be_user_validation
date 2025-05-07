from django.urls import path, include
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from .views import (
    DiditKYCAPIView,
    didit_webhook,
        RetrieveSessionAPIView,
    kyc_test,
    TusDatosAPIView,
    GetServiceToken,   
    ResolveSessionAPIView,
)

app_name = "kyc"

urlpatterns = [
    # Rutas JWT
    path('api/service-token/', GetServiceToken.as_view(), name='service_token'),
    path("api/kyc/", DiditKYCAPIView.as_view(), name="didit_create_session"),
    path("api/webhook/", didit_webhook, name="didit_webhook"),
    path("api/session/<str:document_id>/", RetrieveSessionAPIView.as_view(), name="didit_retrieve_session"),
    path("test/", kyc_test, name="kyc_test"),
    path('api/session/<str:session_id>/resolve/', ResolveSessionAPIView.as_view(), name='reject-session'),
    path('api/tusdatos/<str:document_id>/', TusDatosAPIView.as_view(), name='tus_datos'),
]
