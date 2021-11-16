from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User

class NewUserForm(UserCreationForm):
    #Include the email in the form and make it a required field
    email = forms.EmailField(required=True)

    #Display the form from the model User
    class Meta:
        model = User

        #Fields to display in this order
        fields = ("username", "email", "password1", "password2")

    #Override the 'save' method
    def save(self, commit=True):
        #Create an user object but don't save the data
        user = super(NewUserForm, self).save(commit=False)
        user.email = self.cleaned_data['email'] #Normalize the email

        if commit:
            user.save() #Save the user to the database
        return user
