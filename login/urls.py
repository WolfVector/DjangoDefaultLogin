from django.urls import path
from django.contrib.auth import views as auth_views
from django.contrib.auth.decorators import login_required

from . import views

app_name = "login"
urlpatterns = [
    path('', views.index, name='index'),
    path("register", views.register_req, name="register"),
    path("login", views.login_req, name="login"),
    path("logout", views.logout_req, name="logout"),
    path("password_reset", views.password_reset_req, name='password_reset'),
    path("password_reset/done", login_required(auth_views.PasswordResetDoneView.as_view(template_name="login/password/password_reset_done.html")), name="password_reset_done"),
    path("password/reset/<uidb64>/<token>/", login_required(auth_views.PasswordResetConfirmView.as_view(template_name="login/password/password_reset_confirm.html")), name="password_reset_confirm"),
]
