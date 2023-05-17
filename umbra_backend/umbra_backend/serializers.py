from rest_framework import serializers
from django.contrib.auth.models import User
from rest_framework.validators import UniqueValidator
from django.contrib.auth.password_validation import validate_password

from django.contrib.auth.tokens import PasswordResetTokenGenerator

import threading
import base64

from email.message import EmailMessage
import smtplib

from django.conf import settings

from django.contrib.auth import authenticate
from django.utils.translation import gettext_lazy as _
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "first_name", "last_name", "username"]

# Serializer to Register User


class RegisterSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(
        required=True,
        validators=[UniqueValidator(queryset=User.objects.all())]
    )
    password = serializers.CharField(
        write_only=True, required=True, validators=[validate_password])
    password2 = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ('username', 'password', 'password2',
                  'email', 'first_name', 'last_name')
        extra_kwargs = {
            'first_name': {'required': True},
            'last_name': {'required': True}
        }

    #def validate(self, attrs):
    #    if attrs['password'] != attrs['password2']:
    #        raise serializers.ValidationError(
    #            {"password": "Password fields didn't match."})
    #    return attrs

    def create(self, validated_data):
        user = User.objects.create(
            username=validated_data['username'],
            email=validated_data['email'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
        )
        user.is_active = False
        user.set_password(validated_data['password'])
        user.save()

        #token_generator = PasswordResetTokenGenerator()
        #activation_token = token_generator.make_token(user)
        #print(activation_token)


        """def send(user, email_to, token):
            email = EmailMessage()
            email["From"] = settings.EMAIL_HOST_USER
            email["To"] = email_to
            email["Subject"] = "Verificacion de cuenta umbra"

            uid_bytes = str(user.id).encode('ascii')
            uidb64_bytes = base64.b64encode(uid_bytes)
            uidb64 = uidb64_bytes.decode('ascii')#.strip("=")

            content = "http://localhost:3000/verify?token=" + uidb64.replace("=","%3D") + "%2F" + token

            email.set_content(content)

            smtp = smtplib.SMTP(settings.EMAIL_HOST,
                                port=settings.EMAIL_PORT)
            smtp.starttls()
            smtp.login(settings.EMAIL_HOST_USER, settings.EMAIL_HOST_PASSWORD)
            smtp.sendmail(settings.EMAIL_HOST_USER,
                          email_to, email.as_string())
            smtp.quit()
            print("--- Verification email has been sent")

        thread = threading.Thread(target=send, args=(user,validated_data['email'], activation_token))
        thread.start()"""

        return user
