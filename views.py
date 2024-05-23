from rest_framework.views import APIView
from rest_framework import viewsets
from rest_framework.response import Response
from .serializers import Customer_serializers
from rest_framework.decorators import action
from rest_framework import status
from django.shortcuts import get_object_or_404
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.contrib.auth import get_user_model
from rest_framework.authtoken.models import Token
from django.contrib.auth import authenticate
from .models import Cake,CakeCustomization,Cart,Order,Store
from .serializers import CakeSerializer,CakeCustomizationSerializer,CartSerializer,OrderSerializer,Customer_serializers,StoreSerializer
from django.db import transaction
from django.core.mail import send_mail
import googlemaps
import time
from threading import Thread
import sched
from django.utils.timezone import datetime
from datetime import timedelta
from django.utils.timezone import now
from rest_framework.exceptions import PermissionDenied,MethodNotAllowed
Customer=get_user_model()
class CustomerViewSet(viewsets.ModelViewSet):
    queryset = Customer.objects.all()
    serializer_class = Customer_serializers

    @action(detail=False, methods=['post'])
    def register(self, request):
        email = request.data.get('email')
        phone = request.data.get('phone_no')
        print(email)
        try:
            validate_email(email)
        except ValidationError:
            return Response({'error': 'Invalid email'}, status=status.HTTP_400_BAD_REQUEST)

        if not phone.isdigit() or len(phone) != 10:
            return Response({'error': 'Invalid phone number'}, status=status.HTTP_400_BAD_REQUEST)

        if Customer.objects.filter(email=email).exists():
            return Response({"message": "User already exists with this email"}, status=status.HTTP_400_BAD_REQUEST)

        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['post'])
    def login(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        print(email,password)
        user = authenticate(request, email=email, password=password)
        print(user)
        if user:
            token, _ = Token.objects.get_or_create(user=user)
            return Response({'token': token.key,'message':'login successful'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Invalid email or password'}, status=status.HTTP_401_UNAUTHORIZED)
class CakeViewSet(viewsets.ModelViewSet):
    queryset = Cake.objects.all()
    serializer_class = CakeSerializer
class CakeCustomizationViewSet(viewsets.ModelViewSet):
    queryset = CakeCustomization.objects.all()
    serializer_class = CakeCustomizationSerializer
    @action(detail=False, methods=['get'])
    def get_custom(self, request, pk):
        customization=CakeCustomization.objects.filter(Customer=pk)
        customizationsirializer=CakeCustomizationSerializer(customization,many=True)
        if customizationsirializer.data:
            return Response(customizationsirializer.data)
        return Response({'message':'no customization found for the user'},status=status.HTTP_204_NO_CONTENT)
class CartViewSet(viewsets.ModelViewSet):
    queryset = Cart.objects.all()
    serializer_class = CartSerializer
    # @action(detail=True, methods=['post'])
    def create(self, request, pk=None):
        customer_id = request.data.get('Customer')
        cake_id = request.data.get('Cake')
        quantity = request.data.get('quantity', 1)
        try:
            customer = Customer.objects.get(id=customer_id)
            if not customer:
                return Response({"message": "user not found"}, status=status.HTTP_400_BAD_REQUEST)
            cake = Cake.objects.get(id=cake_id)
            print(cake.price)
            if cake.availability:
                cart = Cart.objects.create(Customer=customer, quantity=quantity,Cake=cake)
                cart.Customization=CakeCustomization.objects.get(id=request.data.get('Customization'))
                print('abc')
                cart.total_amount = int(cake.price) *int(quantity)
                cart.save()
                serializer = CartSerializer(cart)
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            else:
                return Response({"message": "Cake is not available"}, status=status.HTTP_400_BAD_REQUEST)
        except (Customer.DoesNotExist, Cake.DoesNotExist):
            return Response({"message": "Customer or cake not found"}, status=status.HTTP_404_NOT_FOUND)
    def retrieve(self, request, *args, **kwargs):
        # kwargs['pk'] contains the primary key passed in the URL
        pk = kwargs.get('pk')
        try:
            print(pk)
            instance = Cart.objects.filter(Customer_id=pk)
            serializer = CartSerializer(instance,many=True)
            return Response(serializer.data)
        except:
            return Response({"message": "Cart is empty"}, status=status.HTTP_404_NOT_FOUND)
    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response(serializer.data)

    # Override the partial_update method to handle partial updates
    def partial_update(self, request, *args, **kwargs):
        kwargs['partial'] = True
        return self.update(request, *args, **kwargs)

    def perform_update(self, serializer):
        # Update the total price if quantity is changed
        instance = serializer.save()
        cake = instance.Cake  # Assuming only one cake can be associated with a cart
        quantity = serializer.validated_data.get('quantity', instance.quantity)
        instance.total_amount = cake.price * quantity
        instance.save()
scheduler = sched.scheduler(time.time, time.sleep)
# Background thread function to run the scheduler
def run_scheduler():
    while True:
        scheduler.run(blocking=False)
        time.sleep(1)
def schedule_email(send_time,subject, message, recipient_list):
        delay = (send_time - now()).total_seconds()
        scheduler.enter(delay, 1, send_mail, argument=(subject, message, 'abhisheknlee@gmail.com', recipient_list))
Thread(target=run_scheduler, daemon=True).start()
class OrderViewSet(viewsets.ModelViewSet):
    queryset = Order.objects.all()
    serializer_class = OrderSerializer
    def create(self, request):
        cart_id = request.data.get('cart_id',None)
        delivery_address=request.data.get('delivery_address',None)
        try:
            cart = Cart.objects.get(pk=cart_id)
        except:
            return Response({"message": "cart doesent exists"}, status=status.HTTP_400_BAD_REQUEST)
        print(cart.quantity,'zsxdfghjkljhgfdxcfvgbhnjmklkjnhbgvfcxcvbnm,mnbvcxcvbnm,')
        if cart_id==None:
            return Response({"message": "invalid cart details"}, status=status.HTTP_400_BAD_REQUEST)
        if delivery_address==None or len(delivery_address)<=0:
            return Response({"message": "delivery_address is required"}, status=status.HTTP_400_BAD_REQUEST)
        order = Order.objects.create(customer=cart.Customer,cake_customization=cart.Customization,items=cart.Cake,delivery_address=delivery_address,quantity=cart.quantity,total_price=cart.total_amount)
        payment_method=request.data.get('payment_method',None)
        if payment_method:
            if payment_method == 'credit_card':
                card_number = request.data.get('card_number')
                expiry_date = request.data.get('expiry_date')
                cvv = request.data.get('cvv')

                if not card_number or not expiry_date or not cvv:
                    return Response({"message": "Card details are required for credit card payment"}, status=status.HTTP_400_BAD_REQUEST)

                # Validation for credit card details
                if not is_valid_credit_card(card_number, expiry_date, cvv):
                    return Response({"message": "Invalid credit card details"}, status=status.HTTP_400_BAD_REQUEST)

            elif payment_method == 'paypal':
                paypal_email = request.data.get('paypal_email')
                if not paypal_email:
                    return Response({"message": "PayPal email is required for PayPal payment"}, status=status.HTTP_400_BAD_REQUEST)

                # Validation for PayPal email format
                if not is_valid_paypal_email(paypal_email):
                    return Response({"message": "Invalid PayPal email"}, status=status.HTTP_400_BAD_REQUEST)
            order.payment_method=payment_method
            order.payment_status='paid'
            order.order_status='processing'
            order.save()
            subject = 'payement sucessfull '
            message = 'your order is place sucessuflly ,cake Name:'+str(order.items.name)
            recipient = order.customer.email
            print(recipient)
            try:
                send_mail(subject, message, 'abhisheknlee@gmail.com', [recipient])
            except Exception as e:
                return Response({'message': 'Failed to send email', 'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            cart.delete()
        order.save()
        serializer = self.serializer_class(order)
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    def partial_update(self, request, pk=None):
        order = Order.objects.get(pk=pk)
        payment_method=request.data.get('payment_method',None)
        if payment_method:
            if payment_method == 'credit_card':
                card_number = request.data.get('card_number')
                expiry_date = request.data.get('expiry_date')
                cvv = request.data.get('cvv')

                if not card_number or not expiry_date or not cvv:
                    return Response({"message": "Card details are required for credit card payment"}, status=status.HTTP_400_BAD_REQUEST)

                # Validation for credit card details
                if not is_valid_credit_card(card_number, expiry_date, cvv):
                    return Response({"message": "Invalid credit card details"}, status=status.HTTP_400_BAD_REQUEST)

            elif payment_method == 'paypal':
                paypal_email = request.data.get('paypal_email')
                if not paypal_email:
                    return Response({"message": "PayPal email is required for PayPal payment"}, status=status.HTTP_400_BAD_REQUEST)

                # Validation for PayPal email format
                if not is_valid_paypal_email(paypal_email):
                    return Response({"message": "Invalid PayPal email"}, status=status.HTTP_400_BAD_REQUEST)
            order.payment_method=payment_method
            order.payment_status='paid'
            order.order_status='processing'
            subject = 'payement sucessfull '
            message = 'your order is place sucessuflly ,cake Name:'+str(order.items.name)
            recipient = order.customer.email
            print(recipient)
            try:
                send_mail(subject, message, 'abhisheknlee@gmail.com', [recipient])
            except Exception as e:
                return Response({'message': 'Failed to send email', 'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            order.save()
            cart=Cart.objects.filter(Customer_id=order.customer,Cake=order.items)
            print(cart)
            cart.delete()
        else:
            instance = self.get_object()
            serializer = self.get_serializer(instance, data=request.data, partial=True)
            serializer.is_valid(raise_exception=True)
            self.perform_update(serializer)
            return Response(serializer.data,status=status.HTTP_200_OK)
        return Response(OrderSerializer(order).data,status=status.HTTP_200_OK)
    def retrieve(self, request, *args, **kwargs):
        # kwargs['pk'] contains the primary key passed in the URL
        pk = kwargs.get('pk')
        try:
            instance = Order.objects.filter(customer_id=pk)
            serializer = OrderSerializer(instance,many=True)
            return Response(serializer.data)
        except:
            return Response({"message": "no orders"}, status=status.HTTP_404_NOT_FOUND)
    @action(detail=False, methods=['GET'], url_path='delivery_tracking/(?P<id>[^/]+)')
    def  delivery_tracking(self,request,id):
        order_id = id
        try:
            order = Order.objects.get(id=id)
        except Order.DoesNotExist:
            return Response({"message": "Order does not exist"}, status=status.HTTP_404_NOT_FOUND)
        # Initialize Google Maps client
        gmaps = googlemaps.Client(key='AIzaSyBcRflkaeZg8jls3gaA53_rDShtdSQBLhg')
        # Define current location and delivery address (you can hardcode or retrieve from order)
        sweetspot_location= "Tondebavi,karnataka,India"
        delivery_address = order.delivery_address

        # Call Distance Matrix API
        try:
            response = gmaps.distance_matrix(sweetspot_location, delivery_address)
            distance = response['rows'][0]['elements'][0]['distance']['text']
            duration = response['rows'][0]['elements'][0]['duration']['text']
        except Exception as e:
            return Response({"message": "Error retrieving data from Google Distance Matrix API", "error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        duration1 = int(duration.split()[0])
        delivery_time = now() + timedelta(minutes=duration1)
        recipient_list = [order.customer.email]
        remainder_time=delivery_time - timedelta(minutes=5)
        remainder_time1=now()
        # Schedule emails
        schedule_email(remainder_time1,"Your Order has started", f"Your order has been successfully started.It will arrive in {duration1}minutes.", recipient_list)
        schedule_email(remainder_time, "Order arriving soon", "Your order is arriving soon.It will arrive in 5 min.", recipient_list)
        schedule_email(delivery_time,"Your Order has delivered", "Your order has been Successfully Delivered. Enjoy Your Cake!", recipient_list)
        data = {
            "order_id": order_id,
            "delivery_address": delivery_address,
            "distance": distance,
            "duration": duration,
        }
        return Response(data, status=status.HTTP_200_OK)
#admin apis
class StoreViewSet(viewsets.ModelViewSet):
    queryset = Store.objects.all()
    serializer_class = StoreSerializer
    def get_email_from_request(self, request):
        return request.data.get('adminemail') or request.query_params.get('adminemail')
    def list(self, request, *args, **kwargs):
        email = self.get_email_from_request(request)
        if not email:
            raise PermissionDenied("Admin Email is required for this action.")
        if is_admin_user(email):
            return super().list(request, *args, **kwargs)
        raise PermissionDenied("only Admin have access")
    def create(self, request, *args, **kwargs):
        email = self.get_email_from_request(request)
        if not email:
            raise PermissionDenied("Admin Email is required for this action.")
        if is_admin_user(email):
            return super().create(request, *args, **kwargs)
        raise PermissionDenied("only Admin have access")

    def retrieve(self, request, *args, **kwargs):
        email = self.get_email_from_request(request)
        if not email:
            raise PermissionDenied("Admin Email is required for this action.")
        if is_admin_user(email):
            return super().retrieve(request, *args, **kwargs)
        raise PermissionDenied("only Admin have access")
    def update(self, request, *args, **kwargs):
        email = self.get_email_from_request(request)
        if not email:
            raise PermissionDenied("Admin Email is required for this action.")
        if is_admin_user(email):
            return super().update(request, *args, **kwargs)
        raise PermissionDenied("only Admin have access")
    def partial_update(self, request, *args, **kwargs):
        email = self.get_email_from_request(request)
        if not email:
            raise PermissionDenied("Admin Email is required for this action.")
        if is_admin_user(email):
            return super().partial_update(request, *args, **kwargs)
        raise PermissionDenied("only Admin have access")
    def destroy(self, request, *args, **kwargs):
        email = self.get_email_from_request(request)
        if not email:
            raise PermissionDenied("Admin Email is required for this action.")
        if is_admin_user(email):
            return super().destroy(request, *args, **kwargs)
        raise PermissionDenied("only Admin have access")
class CustomerViewSet_admin(viewsets.ModelViewSet):
    queryset = Customer.objects.all()
    serializer_class = Customer_serializers
    def get_email_from_request(self, request):
        return request.data.get('adminemail') or request.query_params.get('adminemail')
    def list(self, request, *args, **kwargs):
        email = self.get_email_from_request(request)
        if not email:
            raise PermissionDenied("Admin Email is required for this action.")
        if is_admin_user(email):
            return super().list(request, *args, **kwargs)
        raise PermissionDenied("Only admins have access.")
    def create(self, request, *args, **kwargs):
        email = self.get_email_from_request(request)
        if not email:
            raise PermissionDenied("Admin Email is required for this action.")
        if is_admin_user(email):
            return super().create(request, *args, **kwargs)
        raise PermissionDenied("Only admins have access.")
    def retrieve(self, request, *args, **kwargs):
        email = self.get_email_from_request(request)
        if not email:
            raise PermissionDenied("Admin Email is required for this action.")
        if is_admin_user(email):
            return super().retrieve(request, *args, **kwargs)
        raise PermissionDenied("Only admins have access.")
    def update(self, request, *args, **kwargs):
        email = self.get_email_from_request(request)
        if not email:
            raise PermissionDenied("Admin Email is required for this action.")
        if is_admin_user(email):
            return super().update(request, *args, **kwargs)
        raise PermissionDenied("Only admins have access.")
    def partial_update(self, request, *args, **kwargs):
        email = self.get_email_from_request(request)
        if not email:
            raise PermissionDenied("Admin Email is required for this action.")
        if is_admin_user(email):
            return super().partial_update(request, *args, **kwargs)
        raise PermissionDenied("Only admins have access.")
    def destroy(self, request, *args, **kwargs):
        email = self.get_email_from_request(request)
        if not email:
            raise PermissionDenied("Admin Email is required for this action.")
        if is_admin_user(email):
            return super().destroy(request, *args, **kwargs)
        raise PermissionDenied("Only admins have access.")
class CakeViewSet_admin(viewsets.ModelViewSet):
    queryset = Cake.objects.all()
    serializer_class = CakeSerializer

    def get_email_from_request(self, request):
        return request.data.get('adminemail') or request.query_params.get('adminemail')

    def retrieve(self, request, *args, **kwargs):
        store_id =kwargs.get('pk')
        if not store_id:
            raise PermissionDenied("Store ID is required for this action.")

        email = self.get_email_from_request(request)
        if not email:
            raise PermissionDenied("Admin Email is required for this action.")
        
        # Assuming you have a function to check if the email belongs to an admin
        if not is_admin_user(email):
            raise PermissionDenied("Only admins have access.")

        # Filter the queryset based on the provided store ID
        queryset = self.queryset.filter(store_id=store_id)
        serializer = self.serializer_class(queryset, many=True)
        return Response(serializer.data)

    def create(self, request, *args, **kwargs):
        email = self.get_email_from_request(request)
        if not email:
            raise PermissionDenied("Admin Email is required for this action.")
        if is_admin_user(email):
            return super().create(request, *args, **kwargs)
        raise PermissionDenied("Only admins have access.")

    def update(self, request, *args, **kwargs):
        email = self.get_email_from_request(request)
        if not email:
            raise PermissionDenied("Admin Email is required for this action.")
        if is_admin_user(email):
            return super().update(request, *args, **kwargs)
        raise PermissionDenied("Only admins have access.")

    def partial_update(self, request, *args, **kwargs):
        email = self.get_email_from_request(request)
        if not email:
            raise PermissionDenied("Admin Email is required for this action.")
        if is_admin_user(email):
            return super().partial_update(request, *args, **kwargs)
        raise PermissionDenied("Only admins have access.")

    def destroy(self, request, *args, **kwargs):
        email = self.get_email_from_request(request)
        if not email:
            raise PermissionDenied("Admin Email is required for this action.")
        if is_admin_user(email):
            return super().destroy(request, *args, **kwargs)
        raise PermissionDenied("Only admins have access.")
class CakeCustomizationViewSet_admin(viewsets.ModelViewSet):
    queryset = CakeCustomization.objects.all()
    serializer_class = CakeCustomizationSerializer
    def get_email_from_request(self, request):
        return request.data.get('adminemail') or request.query_params.get('adminemail')
    def list(self, request, *args, **kwargs):
        raise MethodNotAllowed("GET")
    def retrieve(self, request, *args, **kwargs):
        raise MethodNotAllowed("GET")
    def create(self, request, *args, **kwargs):
        email = self.get_email_from_request(request)
        if not email:
            raise PermissionDenied("Admin Email is required for this action.")
        if is_admin_user(email):
            return super().create(request, *args, **kwargs)
        raise PermissionDenied("Only admins have access.")
    def update(self, request, *args, **kwargs):
        email = self.get_email_from_request(request)
        if not email:
            raise PermissionDenied("Admin Email is required for this action.")
        if is_admin_user(email):
            return super().update(request, *args, **kwargs)
        raise PermissionDenied("Only admins have access.")
    def partial_update(self, request, *args, **kwargs):
        email = self.get_email_from_request(request)
        if not email:
            raise PermissionDenied("Admin Email is required for this action.")
        if is_admin_user(email):
            return super().partial_update(request, *args, **kwargs)
        raise PermissionDenied("Only admins have access.")
    def destroy(self, request, *args, **kwargs):
        email = self.get_email_from_request(request)
        if not email:
            raise PermissionDenied("Admin Email is required for this action.")
        if is_admin_user(email):
            return super().destroy(request, *args, **kwargs)
        raise PermissionDenied("Only admins have access.")
class OrderViewSet_admin(viewsets.ModelViewSet):
    queryset = Order.objects.all()
    serializer_class = OrderSerializer
    def get_email_from_request(self, request):
        return request.data.get('adminemail') or request.query_params.get('adminemail')
    def list(self, request, *args, **kwargs):
        email = self.get_email_from_request(request)
        if not email:
            raise PermissionDenied("Admin Email is required for this action.")
        if is_admin_user(email):
            return super().list(request, *args, **kwargs)
        raise PermissionDenied("Only admins have access.")
    def retrieve(self, request, *args, **kwargs):
        email = self.get_email_from_request(request)
        if not email:
            raise PermissionDenied("Admin Email is required for this action.")
        if is_admin_user(email):
            return super().retrieve(request, *args, **kwargs)
        raise PermissionDenied("Only admins have access.")
    def create(self, request, *args, **kwargs):
        raise MethodNotAllowed("POST")
    def update(self, request, *args, **kwargs):
        email = self.get_email_from_request(request)
        if not email:
            raise PermissionDenied("Admin Email is required for this action.")
        if is_admin_user(email):
            return super().update(request, *args, **kwargs)
        raise PermissionDenied("Only admins have access.")
    def partial_update(self, request, *args, **kwargs):
        email = self.get_email_from_request(request)
        if not email:
            raise PermissionDenied("Admin Email is required for this action.")
        if is_admin_user(email):
            return super().partial_update(request, *args, **kwargs)
        raise PermissionDenied("Only admins have access.")
    def destroy(self, request, *args, **kwargs):
        email = self.get_email_from_request(request)
        if not email:
            raise PermissionDenied("Admin Email is required for this action.")
        if is_admin_user(email):
            return super().destroy(request, *args, **kwargs)
        raise PermissionDenied("Only admins have access.")
import re
import datetime
def is_valid_credit_card(card_number, expiry_date, cvv):
    # Validation for credit card number (dummy implementation)
    if not re.match(r'^[0-9]{16}$', card_number):
        return False
    # Validation for expiry date (dummy implementation)
    if not re.match(r'^\d{2}/\d{2}$', expiry_date):
        return False
    
    # Extract month and year from the expiry_date string
    month, year = map(int, expiry_date.split('/'))
    
    # Get the current month and year
    current_month = datetime.datetime.now().month
    current_year = datetime.datetime.now().year % 100  # Extract last two digits
    
    # Check if the expiry month and year are in the future
    if year < current_year or (year == current_year and month < current_month):
        return False
    # Validation for CVV (dummy implementation)
    if not re.match(r'^\d{3}$', cvv):
        return False
    return True



def is_valid_paypal_email(email):
    # Validation for PayPal email format (dummy implementation)
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        return False
    return True

def is_admin_user(email):
    try:
        user = Customer.objects.get(email=email)
        return user.is_staff
    except Customer.DoesNotExist:
        return False