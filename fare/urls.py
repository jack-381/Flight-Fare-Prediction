from django.urls import path
from . import views

urlpatterns = [
    path('',views.Index, name = "Base"),
    path('Login', views.Login, name = "Login"),
    path('signup', views.SignUp, name = "SignUp"),
    path('Home', views.Transfer, name = 'Home'),
    path('predict',views.predict,name='predict')
]