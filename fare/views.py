from django.shortcuts import redirect, render
from fare.models import User_Info
from django.contrib import messages
from django.http import HttpResponse
import pandas as pd
import sklearn
import pickle
import numpy as np
import hashlib


# Create your views here.
def Index(request):
    return render(request, 'base.html')

def Login(request):
    if request.method == 'POST':
        mid = request.POST["mailid"]
        pas = request.POST["pass"]
        enc_pas = hashlib.sha256(pas.encode())
        if User_Info.objects.filter(email = mid, password = enc_pas.hexdigest()).exists():
            user = User_Info.objects.get(email=mid)
            return render(request,"home.html")
        else :
            messages.error(request,'Invalid Credentials !')
            return redirect('/')

def SignUp(request):
    return render(request,"base.html")

def Transfer(request):
    usr = request.POST["username"]
    mid = request.POST["mailid"]
    pas = request.POST["pass"]
    enc_pas = hashlib.sha256(pas.encode())

    if User_Info.objects.filter(email = mid).exists():
        messages.error(request,'Email_id already exists !')
        return redirect('SignUp')
    else:
        user = User_Info(password=enc_pas.hexdigest() ,username=usr ,email=mid )
        user.save()
        return render(request,"base.html")

def predict(request):
    model = pickle.load(open("en_flight_rf.pkl", "rb"))
    if request.method == "POST":

        # Date_of_Journey
        date_dep = request.POST["Dep_Time"]
        Journey_day = int(pd.to_datetime(date_dep, format="%Y-%m-%dT%H:%M").day)
        Journey_month = int(pd.to_datetime(date_dep, format ="%Y-%m-%dT%H:%M").month)
        # print("Journey Date : ",Journey_day, Journey_month)

        # Departure
        Dep_hour = int(pd.to_datetime(date_dep, format ="%Y-%m-%dT%H:%M").hour)
        Dep_min = int(pd.to_datetime(date_dep, format ="%Y-%m-%dT%H:%M").minute)
        # print("Departure : ",Dep_hour, Dep_min)

        # Arrival
        date_arr = request.POST["Arrival_Time"]
        Arrival_hour = int(pd.to_datetime(date_arr, format ="%Y-%m-%dT%H:%M").hour)
        Arrival_min = int(pd.to_datetime(date_arr, format ="%Y-%m-%dT%H:%M").minute)
        # print("Arrival : ", Arrival_hour, Arrival_min)

        # Duration
        dur_hour = abs(Arrival_hour - Dep_hour)
        dur_min = abs(Arrival_min - Dep_min)
        # print("Duration : ", dur_hour, dur_min)

        # Total Stops
        Total_stops = int(request.POST["stops"])
        # print(Total_stops)

        
        airline=request.POST['airline']
        if(airline=='Jet Airways'):
            Jet_Airways = 1
            IndiGo = 0
            Air_India = 0
            Multiple_carriers = 0
            SpiceJet = 0
            Vistara = 0
            GoAir = 0
            Multiple_carriers_Premium_economy = 0
            Jet_Airways_Business = 0
            Vistara_Premium_economy = 0
            Trujet = 0 

        elif (airline=='IndiGo'):
            Jet_Airways = 0
            IndiGo = 1
            Air_India = 0
            Multiple_carriers = 0
            SpiceJet = 0
            Vistara = 0
            GoAir = 0
            Multiple_carriers_Premium_economy = 0
            Jet_Airways_Business = 0
            Vistara_Premium_economy = 0
            Trujet = 0 

        elif (airline=='Air India'):
            Jet_Airways = 0
            IndiGo = 0
            Air_India = 1
            Multiple_carriers = 0
            SpiceJet = 0
            Vistara = 0
            GoAir = 0
            Multiple_carriers_Premium_economy = 0
            Jet_Airways_Business = 0
            Vistara_Premium_economy = 0
            Trujet = 0 
            
        elif (airline=='Multiple carriers'):
            Jet_Airways = 0
            IndiGo = 0
            Air_India = 0
            Multiple_carriers = 1
            SpiceJet = 0
            Vistara = 0
            GoAir = 0
            Multiple_carriers_Premium_economy = 0
            Jet_Airways_Business = 0
            Vistara_Premium_economy = 0
            Trujet = 0 
            
        elif (airline=='SpiceJet'):
            Jet_Airways = 0
            IndiGo = 0
            Air_India = 0
            Multiple_carriers = 0
            SpiceJet = 1
            Vistara = 0
            GoAir = 0
            Multiple_carriers_Premium_economy = 0
            Jet_Airways_Business = 0
            Vistara_Premium_economy = 0
            Trujet = 0 
            
        elif (airline=='Vistara'):
            Jet_Airways = 0
            IndiGo = 0
            Air_India = 0
            Multiple_carriers = 0
            SpiceJet = 0
            Vistara = 1
            GoAir = 0
            Multiple_carriers_Premium_economy = 0
            Jet_Airways_Business = 0
            Vistara_Premium_economy = 0
            Trujet = 0

        elif (airline=='GoAir'):
            Jet_Airways = 0
            IndiGo = 0
            Air_India = 0
            Multiple_carriers = 0
            SpiceJet = 0
            Vistara = 0
            GoAir = 1
            Multiple_carriers_Premium_economy = 0
            Jet_Airways_Business = 0
            Vistara_Premium_economy = 0
            Trujet = 0

        elif (airline=='Multiple carriers Premium economy'):
            Jet_Airways = 0
            IndiGo = 0
            Air_India = 0
            Multiple_carriers = 0
            SpiceJet = 0
            Vistara = 0
            GoAir = 0
            Multiple_carriers_Premium_economy = 1
            Jet_Airways_Business = 0
            Vistara_Premium_economy = 0
            Trujet = 0

        elif (airline=='Jet Airways Business'):
            Jet_Airways = 0
            IndiGo = 0
            Air_India = 0
            Multiple_carriers = 0
            SpiceJet = 0
            Vistara = 0
            GoAir = 0
            Multiple_carriers_Premium_economy = 0
            Jet_Airways_Business = 1
            Vistara_Premium_economy = 0
            Trujet = 0

        elif (airline=='Vistara Premium economy'):
            Jet_Airways = 0
            IndiGo = 0
            Air_India = 0
            Multiple_carriers = 0
            SpiceJet = 0
            Vistara = 0
            GoAir = 0
            Multiple_carriers_Premium_economy = 0
            Jet_Airways_Business = 0
            Vistara_Premium_economy = 1
            Trujet = 0
            
        elif (airline=='Trujet'):
            Jet_Airways = 0
            IndiGo = 0
            Air_India = 0
            Multiple_carriers = 0
            SpiceJet = 0
            Vistara = 0
            GoAir = 0
            Multiple_carriers_Premium_economy = 0
            Jet_Airways_Business = 0
            Vistara_Premium_economy = 0
            Trujet = 1

        else:
            Jet_Airways = 0
            IndiGo = 0
            Air_India = 0
            Multiple_carriers = 0
            SpiceJet = 0
            Vistara = 0
            GoAir = 0
            Multiple_carriers_Premium_economy = 0
            Jet_Airways_Business = 0
            Vistara_Premium_economy = 0
            Trujet = 0

        # print(Jet_Airways,
        #     IndiGo,
        #     Air_India,
        #     Multiple_carriers,
        #     SpiceJet,
        #     Vistara,
        #     GoAir,
        #     Multiple_carriers_Premium_economy,
        #     Jet_Airways_Business,
        #     Vistara_Premium_economy,
        #     Trujet)

        Source = request.POST["Source"]
        if (Source == 'Banglore'):
            Source_Banglore = 1
            Source_Delhi = 0
            Source_Kolkata = 0
            Source_Mumbai = 0
            Source_Chennai = 0

        if (Source == 'Delhi'):
            Source_Banglore = 0
            Source_Delhi = 1
            Source_Kolkata = 0
            Source_Mumbai = 0
            Source_Chennai = 0

        elif (Source == 'Kolkata'):
            Source_Banglore = 0
            Source_Delhi = 0
            Source_Kolkata = 1
            Source_Mumbai = 0
            Source_Chennai = 0

        elif (Source == 'Mumbai'):
            Source_Banglore = 0
            Source_Delhi = 0
            Source_Kolkata = 0
            Source_Mumbai = 1
            Source_Chennai = 0

        elif (Source == 'Chennai'):
            Source_Banglore = 0
            Source_Delhi = 0
            Source_Kolkata = 0
            Source_Mumbai = 0
            Source_Chennai = 1

        else:
            Source_Banglore = 0
            Source_Delhi = 0
            Source_Kolkata = 0
            Source_Mumbai = 0
            Source_Chennai = 0

        
        Source = request.POST["Destination"]
        if (Source == 'Banglore'):
            Destination_Banglore = 1
            Destination_Cochin = 0
            Destination_Delhi = 0
            Destination_New_Delhi = 0
            Destination_Hyderabad = 0
            Destination_Kolkata = 0

        if (Source == 'Cochin'):
            Destination_Banglore = 0
            Destination_Cochin = 1
            Destination_Delhi = 0
            Destination_New_Delhi = 0
            Destination_Hyderabad = 0
            Destination_Kolkata = 0
        
        elif (Source == 'Delhi'):
            Destination_Banglore = 0
            Destination_Cochin = 0
            Destination_Delhi = 1
            Destination_New_Delhi = 0
            Destination_Hyderabad = 0
            Destination_Kolkata = 0

        elif (Source == 'New_Delhi'):
            Destination_Banglore = 0
            Destination_Cochin = 0
            Destination_Delhi = 0
            Destination_New_Delhi = 1
            Destination_Hyderabad = 0
            Destination_Kolkata = 0

        elif (Source == 'Hyderabad'):
            Destination_Banglore = 0
            Destination_Cochin = 0
            Destination_Delhi = 0
            Destination_New_Delhi = 0
            Destination_Hyderabad = 1
            Destination_Kolkata = 0

        elif (Source == 'Kolkata'):
            Destination_Banglore = 0
            Destination_Cochin = 0
            Destination_Delhi = 0
            Destination_New_Delhi = 0
            Destination_Hyderabad = 0
            Destination_Kolkata = 1

        else:
            Destination_Banglore = 0
            Destination_Cochin = 0
            Destination_Delhi = 0
            Destination_New_Delhi = 0
            Destination_Hyderabad = 0
            Destination_Kolkata = 0

        

        inp=[
            Total_stops,
            Journey_day,
            Journey_month,
            Dep_hour,
            Dep_min,
            Arrival_hour,
            Arrival_min,
            dur_hour,
            dur_min,
            Air_India,
            GoAir,
            IndiGo,
            Jet_Airways,
            Jet_Airways_Business,
            Multiple_carriers,
            Multiple_carriers_Premium_economy,
            SpiceJet,
            Trujet,
            Vistara,
            Vistara_Premium_economy,
            Source_Banglore,
            Source_Chennai,
            Source_Delhi,
            Source_Kolkata,
            Source_Mumbai,
            Destination_Banglore,
            Destination_Cochin,
            Destination_Delhi,
            Destination_Hyderabad,
            Destination_Kolkata,
            Destination_New_Delhi
        ]

        from Crypto.Cipher import AES
        def encrypt_message(message, key):
            message = message.encode('utf-8')
            padding = 16 - (len(message) % 16)
            message += bytes([padding] * padding)
            key = key[:16].encode('utf-8')
            cipher = AES.new(key, AES.MODE_ECB)
            ciphertext = cipher.encrypt(message)
            return ciphertext

        def decrypt_message(ciphertext, key):
            key = key[:16].encode()
            cipher = AES.new(key, AES.MODE_ECB)
            message = cipher.decrypt(ciphertext)
            padding = message[-1]
            message = message[:-padding]
            message = message.decode()
            return message

        key = "flight price predictor"
        inp = [str(x) for x in inp]
        enc = [encrypt_message(val, key) for val in inp]
        enc_int = np.array([int.from_bytes(val, byteorder='little') for val in enc]).reshape(1,-1)
        
        prediction=model.predict(enc_int)

        output=round(prediction[0],2)
        output=str(output)

        return render(request,'home.html',{"output":output})
    
