from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from .forms import CustomAuthenticationForm


def user_register(request):
    if request.method == "POST":
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            return redirect('dash:index')
    else:
        form = UserCreationForm()

    return render(request, 'authentication/register.html', {'form': form})

def user_login(request):
    if request.method == "POST":
        form = CustomAuthenticationForm(request, data=request.POST)
        if form.is_valid():
            username = form.data.get('username')
            password = form.data.get('password')
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                return redirect('dash:index')

    else:
        form = CustomAuthenticationForm()

    return render(request, 'authentication/login.html', {'form': form})

def user_logout(request):
    logout(request)
    return redirect('authentication:login')