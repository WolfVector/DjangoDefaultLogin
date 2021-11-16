from django.core.mail import send_mail, BadHeaderError
from django.http import HttpResponse
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, url_has_allowed_host_and_scheme
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes, iri_to_uri
from django.shortcuts import render, redirect, get_object_or_404
from .forms import NewUserForm
from django.contrib.auth import login, logout, authenticate
from django.contrib import messages
from django.contrib.auth.forms import AuthenticationForm, PasswordResetForm
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required, user_passes_test
from .decorator import user_is_not_logged_in


def index(request):
    return render(request=request, template_name="login/index.html")

def register_req(request):
    if request.method == 'POST': #If the request is a POST...
        form = NewUserForm(request.POST) #Create a form with user data
        if form.is_valid(): #Validate the form
            user = form.save() #Save it
            messages.success(request, "Registration successful")
            return redirect("login:login")
    else:
        form = NewUserForm() #Create a form and pass it to the view
    return render(request=request, template_name="login/register.html", context={'register_form': form})

#If the user is logged, then redirect to index
@user_passes_test(user_is_not_logged_in, login_url='login:index')
def login_req(request):
    if request.method == 'POST': #If the method is a post
        form = AuthenticationForm(request, data=request.POST) #Create an authentication form with the user data
        if form.is_valid(): #This form is goint yo try to authenticate, so it is no necessary to check below
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password) #Check the credentials

            login(request, user) #Save the credentials in a session
            
            #If the 'next' url exists and is valid, then redirect to it
            #else, redirect to index
            #The None parameter can be replaced by allowed external hosts
            #The third parameter required_https=False is self-explanatory 
            if url_has_allowed_host_and_scheme(request.GET.get('next', 'login:index'), None):
                url = iri_to_uri(request.GET.get('next', 'login:index'))
                return redirect(url)

            return redirect('login:index')
    else:
        form = AuthenticationForm()
    return render(request=request, template_name="login/login.html", context={"login_form": form})

#If the user is not logged, redirect to settings.URL_LOGIN
@login_required
def password_reset_req(request):
    if request.method == "POST": #If request is POST
        password_reset_form = PasswordResetForm(request.POST) #Create a password reset form and pass the user data
        if password_reset_form.is_valid(): #If the form is vali...
            data = password_reset_form.cleaned_data['email'] #Normalize the email
            user = get_object_or_404(User, email=data) #Check if the email exists

            subject = "Password Reset Requested"
            email_template_name = "login/password/password_reset_email.txt"
            c = {
            "email": user.email,
            "domain": "127.0.0.1:8000",
            "site_name": "Website",
            "uid": urlsafe_base64_encode(force_bytes(user.pk)),
            "user": user,
            "token": default_token_generator.make_token(user),
            "protocol": "http"
            }
            email = render_to_string(email_template_name, c)

            #subject, content and data, from, to
            try:
                send_mail(subject, email, 'admin@example.com', [user.email], fail_silently=False)
            except BadHeaderError:
                return HttpResponse('Invalid header found')
            return redirect("login:password_reset_done")

    #Create a password reset form and pass it to the view
    password_reset_form = PasswordResetForm()
    return render(request=request, template_name="login/password/password_reset.html", context={"password_reset_form": password_reset_form})

def logout_req(request):
    logout(request) #Destroy the credentials
    return redirect("login:index")
