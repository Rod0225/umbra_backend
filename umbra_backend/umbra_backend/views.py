# Create your views here.
import json
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework import authentication, permissions

import os
from django.conf import settings

from rest_framework.renderers import JSONRenderer
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser

from .serializers import UserSerializer, RegisterSerializer
from django.contrib.auth.models import User
from rest_framework.authentication import TokenAuthentication
from rest_framework import generics
from rest_framework.authtoken.models import Token
# Class based view to Get User Details using Token Authentication

import threading
import base64

from email.message import EmailMessage
import smtplib

import datetime

from rest_framework.compat import coreapi, coreschema
from rest_framework.schemas import coreapi as coreapi_schema
from rest_framework.schemas import ManualSchema
from rest_framework.authtoken.serializers import AuthTokenSerializer

from django.contrib.auth.tokens import PasswordResetTokenGenerator

class RegisterUser(generics.CreateAPIView):
    permission_classes = (AllowAny,)
    serializer_class = RegisterSerializer


class LoginUser(generics.CreateAPIView):
    parser_classes = (MultiPartParser, FormParser, JSONParser)
    renderer_classes = (JSONRenderer,)
    serializer_class = AuthTokenSerializer

    if coreapi_schema.is_enabled():
        schema = ManualSchema(
            fields=[
                coreapi.Field(
                    name="username",
                    required=True,
                    location='form',
                    schema=coreschema.String(
                        title="Username",
                        description="Valid username for authentication",
                    ),
                ),
                coreapi.Field(
                    name="password",
                    required=True,
                    location='form',
                    schema=coreschema.String(
                        title="Password",
                        description="Valid password for authentication",
                    ),
                ),
            ],
            encoding="application/json",
        )

    def get_serializer_context(self):
        return {
            'request': self.request,
            'format': self.format_kwarg,
            'view': self
        }

    def get_serializer(self, *args, **kwargs):
        kwargs['context'] = self.get_serializer_context()
        return self.serializer_class(*args, **kwargs)

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        token, created = Token.objects.get_or_create(user=user)
        now = datetime.datetime.now()
        user.last_login = str(now)
        user.save()
        return Response({'token': token.key})

"""class VerifyUser(generics.CreateAPIView):
    permission_classes = (AllowAny,)
    #serializer_class = RegisterSerializer

    def post(self, request, *args, **kwargs):

        uidb64 = request.data['uid']
        token = request.data['token']

        uidb64_bytes = uidb64.encode('ascii')
        uid_bytes = base64.b64decode(uidb64_bytes)
        uid = uid_bytes.decode('ascii')

        user = User.objects.get(id=int(uid))

        print(uid, token)

        token_generator = PasswordResetTokenGenerator()

        print(user.is_active)

        if not user.is_active:
            if token_generator.check_token(user, token):
                user.is_active = True
                user.save()
                return Response("User verified successfully")
            else:
                return Response("Tokens don't match")
        else:
            return Response("The user is already verified")"""