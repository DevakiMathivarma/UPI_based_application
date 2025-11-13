# core/views.py
from django.shortcuts import render, redirect
from django.urls import reverse
from django.contrib import messages
from django.contrib.auth import login as auth_login, logout as auth_logout, get_user_model
from django.contrib.auth.decorators import login_required
from django.db import transaction
from django.utils import timezone
from django.http import JsonResponse, HttpResponseBadRequest
import secrets
import datetime

from .models import MobileOTP
from .forms import RegistrationForm, LoginOTPForm, ResendOTPForm

from django.core.mail import send_mail
import random
import datetime
import logging
logger = logging.getLogger(__name__)
User = get_user_model()

# email otp view
# ================= EMAIL OTP HELPERS =====================

OTP_LENGTH = 6
OTP_EXPIRY_MINUTES = 5
MAX_VERIFY_ATTEMPTS = 5

def generate_email_otp(length=OTP_LENGTH):
    """Generate a random numeric OTP."""
    return str(random.randint(100000, 999999))

def send_email_otp(user, purpose):
    """Create OTP, store it in DB, and send it via email."""
    # Mark any previous unused OTPs as used
    MobileOTP.objects.filter(user=user, used=False, purpose=purpose).update(used=True)

    otp_code = generate_email_otp()
    expiry = timezone.now() + datetime.timedelta(minutes=OTP_EXPIRY_MINUTES)

    MobileOTP.objects.create(
        user=user,
        otp=otp_code,
        expires_at=expiry,
        purpose=purpose,
        used=False
    )

    subject = "Your GapyPay OTP Verification Code"
    message = f"Hello {user.username},\n\nYour one-time password (OTP) is: {otp_code}\nThis OTP is valid for {OTP_EXPIRY_MINUTES} minutes.\n\nThanks,\nGapyPay Team"
    from_email = "noreply@gapypay.com"
    send_mail(subject, message, from_email, [user.email], fail_silently=False)

    logger.info(f"[EMAIL OTP] Sent to {user.email} | OTP: {otp_code}")
    return otp_code


def register_view(request):
    """Handle user registration with email OTP verification."""
    if request.method == 'GET':
        return render(request, 'core/register.html')

    username = request.POST.get('username')
    email = request.POST.get('email')
    phone = request.POST.get('phone')
    password = request.POST.get('password')
    confirm_password = request.POST.get('confirm_password')

    # Validation checks
    if not all([username, email, phone, password, confirm_password]):
        messages.error(request, "All fields are required.")
        return render(request, 'core/register.html')

    if password != confirm_password:
        messages.error(request, "Passwords do not match.")
        return render(request, 'core/register.html')

    if User.objects.filter(username=username).exists():
        messages.error(request, "Username already exists.")
        return render(request, 'core/register.html')

    if User.objects.filter(email=email).exists():
        messages.error(request, "Email already registered.")
        return render(request, 'core/register.html')

    # Create user and send OTP
    with transaction.atomic():
        user = User.objects.create_user(
            username=username,
            email=email,
            phone_number=phone,
            is_phone_verified=False
        )
        user.set_password(password)
        user.save()

        send_email_otp(user, purpose='REGISTER')

    messages.success(request, f"Account created! OTP sent to {email} for verification.")
    return redirect(f"{reverse('core:login')}?username={username}")



# email otp loginview
from django.contrib.auth import authenticate

def login_view(request):
    if request.method == 'GET':
        return render(request, 'core/login.html')
    logger.info('coming here ')
    # Which button was clicked?
    if 'password' in request.POST:
        # Normal username + password login
        username = request.POST.get('username')
        password = request.POST.get('password')
        logger.info(username)
        logger.info(password)
        user = authenticate(request, username=username, password=password)
        if user:
            auth_login(request, user)
            messages.success(request, "Logged in successfully.")
            return redirect('core:dashboard')
        else:
            messages.error(request, "Invalid username or password.")
            return render(request, 'core/login.html')

    elif 'send_otp' in request.POST:
        # Send OTP to user email
        username = request.POST.get('username')
        user = User.objects.filter(username=username).first()
        if not user:
            messages.error(request, "User not found.")
            return render(request, 'core/login.html')

        send_email_otp(user, 'LOGIN')
        messages.success(request, f"OTP sent to {user.email}. Check your inbox.")
        return render(request, 'core/login.html', {'otp_sent': True, 'username': username})

    elif 'verify_otp' in request.POST:
        username = request.POST.get('username')
        otp_input = request.POST.get('otp')

        user = User.objects.filter(username=username).first()
        if not user:
            messages.error(request, "User not found.")
            return render(request, 'core/login.html')

        otp_obj = MobileOTP.objects.filter(user=user, used=False, purpose='LOGIN').order_by('-created_at').first()
        if not otp_obj:
            messages.error(request, "No active OTP found. Please request a new OTP.")
            return render(request, 'core/login.html', {'otp_sent': True, 'username': username})

        # Check expiry
        if otp_obj.is_expired():
            otp_obj.mark_used()
            messages.error(request, "OTP expired. Please request a new one.")
            return render(request, 'core/login.html', {'username': username})

        # Check attempts
        if otp_obj.attempts >= MAX_VERIFY_ATTEMPTS:
            otp_obj.mark_used()
            messages.error(request, "Too many attempts. Please request a new OTP.")
            return render(request, 'core/login.html', {'username': username})

        # Verify OTP
        if otp_input != otp_obj.otp:
            otp_obj.attempts += 1
            otp_obj.save()
            remaining = MAX_VERIFY_ATTEMPTS - otp_obj.attempts
            messages.error(request, f"Invalid OTP. {remaining} attempts remaining.")
            return render(request, 'core/login.html', {'otp_sent': True, 'username': username})

        # OTP correct → mark used, log in
        otp_obj.mark_used()
        auth_login(request, user)
        messages.success(request, "Logged in successfully.")
        return redirect('core:dashboard')

    return render(request, 'core/login.html')



def logout_view(request):
    """Logout and redirect to login."""
    auth_logout(request)
    messages.info(request, "You have been logged out.")
    return redirect('core:login')

def is_ajax(request):
    return request.headers.get('x-requested-with') == 'XMLHttpRequest'

from django.views.decorators.http import require_POST
from django.http import JsonResponse
from django.utils import timezone
import datetime
from django.core.mail import send_mail
import random
import socket

@require_POST
def resend_otp_view(request):
    """
    Resend OTP to user's registered email address.
    Works for AJAX and normal POST requests.
    """
    username = request.POST.get('username')
    try:
        print
        logger.info("host ",settings.EMAIL_HOST)
        logger.info("port", settings.EMAIL_PORT)
        socket.create_connection((settings.EMAIL_HOST, settings.EMAIL_PORT), timeout=5)
    except Exception as e:
        logger.info(e)
        messages.error(request, "Email server not reachable right now.")
        return redirect("login")
    if not username:
        if request.headers.get('x-requested-with') == 'XMLHttpRequest':
            return JsonResponse({'ok': False, 'message': 'Username is required.'}, status=400)
        messages.error(request, "Username is required.")
        return redirect('core:login')

    # Find user
    user = User.objects.filter(username__iexact=username).first()
    if not user:
        if request.headers.get('x-requested-with') == 'XMLHttpRequest':
            return JsonResponse({'ok': False, 'message': 'User not found.'}, status=404)
        messages.error(request, "User not found.")
        return redirect('core:login')

    # Throttle: prevent spamming OTP
    last_otp = MobileOTP.objects.filter(user=user).order_by('-created_at').first()
    if last_otp and (timezone.now() - last_otp.created_at).total_seconds() < 60:
        wait = 60 - int((timezone.now() - last_otp.created_at).total_seconds())
        if request.headers.get('x-requested-with') == 'XMLHttpRequest':
            return JsonResponse({'ok': False, 'message': f'Please wait {wait}s before resending OTP.'}, status=429)
        messages.error(request, f"Please wait {wait}s before resending OTP.")
        return redirect('core:login')

    # Invalidate previous unused OTPs
    MobileOTP.objects.filter(user=user, used=False, purpose='LOGIN').update(used=True)

    # Generate new OTP
    otp_code = str(random.randint(100000, 999999))
    expiry = timezone.now() + datetime.timedelta(minutes=5)
    MobileOTP.objects.create(
        user=user,
        otp=otp_code,
        expires_at=expiry,
        used=False,
        purpose='LOGIN'
    )

    # Send OTP via email
    subject = "Your GapyPay Login OTP"
    message = f"Dear {user.username},\n\nYour new OTP is: {otp_code}\nIt will expire in 5 minutes.\n\nThanks,\nGapyPay Team"
    try:
        send_mail(subject, message, settings.EMAIL_HOST, [user.email], fail_silently=False)
    except Exception as e:
        logger.info(e)

    logger.info(f"[EMAIL RESEND OTP] Sent to {user.email} | OTP: {otp_code}")

    # For AJAX requests (JS fetch in your login.html)
    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        return JsonResponse({'ok': True, 'message': f'OTP resent successfully to {user.email}.'})

    # For normal form submit
    messages.success(request, f"OTP resent successfully to {user.email}.")
    return redirect('core:login')



from django.views.decorators.http import require_POST
from django.http import JsonResponse
from django.contrib.auth import login as auth_login, authenticate
from django.utils import timezone
import datetime

@require_POST
def ajax_verify_otp(request):
    """
    AJAX endpoint: verify OTP and login user.
    Expects POST: username, otp
    Returns JSON: { ok: bool, message: str, redirect: url }
    """
    username = request.POST.get('username', '').strip()
    otp_input = request.POST.get('otp', '').strip()

    if not username or not otp_input:
        return JsonResponse({'ok': False, 'message': 'Username and OTP are required.'}, status=400)

    user = User.objects.filter(username__iexact=username).first()
    if not user:
        return JsonResponse({'ok': False, 'message': 'User not found.'}, status=404)

    # Find the latest unused OTP for LOGIN purpose
    otp_obj = MobileOTP.objects.filter(user=user, used=False, purpose='LOGIN').order_by('-created_at').first()
    if not otp_obj:
        return JsonResponse({'ok': False, 'message': 'No active OTP found. Please request again.'}, status=400)

    # Expiry
    if otp_obj.expires_at < timezone.now():
        otp_obj.used = True
        otp_obj.save()
        return JsonResponse({'ok': False, 'message': 'OTP expired. Request a new one.'}, status=400)

    # Attempts limit
    MAX_VERIFY = getattr(settings, 'MAX_VERIFY_ATTEMPTS', 5)
    if getattr(otp_obj, 'attempts', 0) >= MAX_VERIFY:
        otp_obj.used = True
        otp_obj.save()
        return JsonResponse({'ok': False, 'message': 'Too many attempts. OTP invalidated.'}, status=400)

    # Check OTP
    if otp_obj.otp != otp_input:
        otp_obj.attempts = (otp_obj.attempts or 0) + 1
        otp_obj.save()
        remaining = MAX_VERIFY - otp_obj.attempts
        return JsonResponse({'ok': False, 'message': f'Invalid OTP. {remaining} attempts left.'}, status=400)

    # OTP correct: mark used and login
    otp_obj.used = True
    otp_obj.save()

    # Mark user as verified if desired
    user.is_phone_verified = True
    user.save()

    # Login user
    auth_login(request, user)

    return JsonResponse({'ok': True, 'message': 'OTP verified. Logging in...', 'redirect': reverse('core:dashboard')})

# 


# # Configurable constants
# OTP_LENGTH = 6
# OTP_EXPIRY_MINUTES = 5
# RESEND_COOLDOWN_SECONDS = 60
# MAX_OTPS_PER_HOUR = 5
# MAX_VERIFY_ATTEMPTS = 5


# # ----------------- Helpers -----------------
# def generate_otp(length=OTP_LENGTH):
#     """Return zero-padded numeric OTP string."""
#     max_val = 10 ** length
#     return str(secrets.randbelow(max_val)).zfill(length)


# # --- Twilio SMS Integration ---
# from twilio.rest import Client
# from django.conf import settings

# def send_sms(phone, message):
#     """
#     Sends an SMS using Twilio.
#     Falls back to console print if Twilio is not configured.
#     """
#     sid = getattr(settings, 'TWILIO_ACCOUNT_SID', '')
#     token = getattr(settings, 'TWILIO_AUTH_TOKEN', '')
#     from_num = getattr(settings, 'TWILIO_PHONE_NUMBER', '')

#     if not sid or not token or not from_num:
#         # Fallback: print if Twilio is not configured (useful for dev)
#         logger.info(f"[SMS fallback] To: {phone} | Msg: {message}")
#         return False

#     try:
#         client = Client(sid, token)
#         msg = client.messages.create(
#             body=message,
#             from_=from_num,
#             to=phone
#         )
#         logger.info(f"[Twilio SMS] Sent to {phone}, SID: {msg.sid}")
#         return True
#     except Exception as e:
#         logger.info(f"[Twilio Error] Failed to send SMS to {phone}: {e}")
#         return False


# def can_send_otp_for_phone(phone):
#     """Allow up to MAX_OTPS_PER_HOUR OTPs per phone (DB-based)."""
#     one_hour_ago = timezone.now() - datetime.timedelta(hours=1)
#     return MobileOTP.objects.filter(user__phone_number=phone, created_at__gte=one_hour_ago).count() < MAX_OTPS_PER_HOUR


# def last_otp_seconds_ago_for_user(user):
#     last = MobileOTP.objects.filter(user=user).order_by('-created_at').first()
#     if not last:
#         return None
#     return int((timezone.now() - last.created_at).total_seconds())


# def create_mobile_otp_and_send(user, purpose):
#     """
#     Create a MobileOTP row (revoking old unused ones), send the OTP via SMS stub,
#     and return the OTP object and the raw code (for testing).
#     """
#     # Mark previous unused OTPs for same purpose as used (to avoid multiple valid codes)
#     MobileOTP.objects.filter(user=user, used=False, purpose=purpose).update(used=True)

#     otp_code = generate_otp()
#     expires_at = timezone.now() + datetime.timedelta(minutes=OTP_EXPIRY_MINUTES)
#     otp_obj = MobileOTP.objects.create(user=user, otp=otp_code, expires_at=expires_at, used=False, purpose=purpose)
#     message = f"Your verification code is {otp_code}. It expires in {OTP_EXPIRY_MINUTES} minutes."
#     send_sms(user.phone_number, message)
#     return otp_obj, otp_code


# ----------------- Views -----------------
def home_view(request):
    # Simple landing: redirect to login
    return redirect('core:login')


# def register_view(request):
#     """
#     GET: show registration form
#     POST: validate, create or reuse user (if unverified), create OTP and send, redirect to login
#     """
#     if request.method == 'GET':
#         form = RegistrationForm()
#         return render(request, 'core/register.html', {'form': form})

#     # POST
#     form = RegistrationForm(request.POST)
#     if not form.is_valid():
#         return render(request, 'core/register.html', {'form': form})

#     username = form.cleaned_data['username']
#     email = form.cleaned_data['email']
#     phone = form.cleaned_data['phone']  # normalized E.164 from the form

#     # Check for existing users
#     existing_by_username = User.objects.filter(username__iexact=username).first()
#     existing_by_email = User.objects.filter(email__iexact=email).first()
#     existing_by_phone = User.objects.filter(phone_number=phone).first()

#     if existing_by_username and existing_by_username.phone_number != phone:
#         form.add_error('username', "Username is already taken.")
#         return render(request, 'core/register.html', {'form': form})

#     if existing_by_email and existing_by_email.phone_number != phone:
#         form.add_error('email', "Email already registered.")
#         return render(request, 'core/register.html', {'form': form})

#     if existing_by_phone and existing_by_phone.is_phone_verified:
#         messages.error(request, "Phone already registered. Please login.")
#         return redirect('core:login')

#     # Create or update user in atomic transaction
#     with transaction.atomic():
#         if existing_by_phone:
#             user = existing_by_phone
#             # update username/email if blank
#             if not user.username:
#                 user.username = username
#             if not user.email:
#                 user.email = email
#             user.save()
#         else:
#             # Create a new user with unusable password (OTP-based)
#             user = User.objects.create_user(username=username, email=email)
#             user.phone_number = phone
#             user.is_phone_verified = False
#             user.set_unusable_password()
#             user.save()

#         # Throttle check
#         if not can_send_otp_for_phone(phone):
#             messages.error(request, "Too many OTP requests for this phone. Try again later.")
#             return redirect('core:register')

#         # Create OTP and send
#         create_mobile_otp_and_send(user, purpose='REGISTER')

#     messages.success(request, f"OTP sent to {phone}. Please enter username and OTP to login.")
#     return redirect(f"{reverse('core:login')}?username={username}")


# def login_view(request):
#     """
#     GET: show login form (username prefill optional)
#     POST: verify OTP and log user in
#     """
#     if request.method == 'GET':
#         pre_username = request.GET.get('username', '')
#         form = LoginOTPForm(initial={'username': pre_username})
#         return render(request, 'core/login.html', {'form': form, 'prefill_username': pre_username})

#     # POST
#     form = LoginOTPForm(request.POST)
#     if not form.is_valid():
#         return render(request, 'core/login.html', {'form': form})

#     username = form.cleaned_data['username']
#     otp_input = form.cleaned_data['otp']

#     user = User.objects.filter(username__iexact=username).first()
#     if not user:
#         form.add_error('username', "Invalid username.")
#         return render(request, 'core/login.html', {'form': form})

#     # Get latest unused OTP (REGISTER or LOGIN)
#     otp_obj = MobileOTP.objects.filter(user=user, used=False).order_by('-created_at').first()
#     if not otp_obj:
#         messages.error(request, "No active OTP found. Please request a new OTP.")
#         return redirect('core:login')

#     # Expiry check
#     if otp_obj.expires_at < timezone.now():
#         otp_obj.used = True
#         otp_obj.save()
#         messages.error(request, "OTP expired. Please request a new OTP.")
#         return redirect('core:login')

#     # Attempts check
#     if getattr(otp_obj, 'attempts', 0) >= MAX_VERIFY_ATTEMPTS:
#         otp_obj.used = True
#         otp_obj.save()
#         messages.error(request, "Maximum verification attempts reached. Please request a new OTP.")
#         return redirect('core:login')

#     # Verify OTP (plain text compare here - change to hashed compare if you hash OTPs)
#     if otp_obj.otp != otp_input:
#         otp_obj.attempts = (otp_obj.attempts or 0) + 1
#         otp_obj.save()
#         remaining = MAX_VERIFY_ATTEMPTS - otp_obj.attempts
#         messages.error(request, f"Invalid OTP. {remaining} attempts remaining.")
#         return render(request, 'core/login.html', {'form': form})

#     # OTP correct -> mark used, mark user verified, login
#     with transaction.atomic():
#         otp_obj.used = True
#         otp_obj.save()
#         user.is_phone_verified = True
#         user.save()
#         auth_login(request, user)

#     messages.success(request, "Logged in successfully.")
#     return redirect('core:dashboard')

# from django.views.decorators.http import require_POST

# @require_POST
# def resend_otp_view(request):
#     """
#     Accepts POST (form or AJAX) to resend OTP given username or phone (ResendOTPForm).
#     Returns JSON for AJAX; otherwise redirects back to login with message.
#     """
#     form = ResendOTPForm(request.POST)
#     if not form.is_valid():
#         if is_ajax(request):
#             return JsonResponse({'ok': False, 'errors': form.errors}, status=400)
#         # render login with form errors (non-AJAX)
#         return render(request, 'core/login.html', {'form': form})

#     user = form.cleaned_data['user']

#     # Cooldown check
#     secs = last_otp_seconds_ago_for_user(user)
#     if secs is not None and secs < RESEND_COOLDOWN_SECONDS:
#         wait = RESEND_COOLDOWN_SECONDS - secs
#         if is_ajax(request):
#             return JsonResponse({'ok': False, 'message': f'Please wait {wait} seconds before resending.'}, status=429)
#         messages.error(request, f"Please wait {wait} seconds before resending OTP.")
#         return redirect('core:login')

#     # Per-hour throttle
#     if not can_send_otp_for_phone(user.phone_number):
#         if is_ajax(request):
#             return JsonResponse({'ok': False, 'message': 'Too many OTP requests. Try later.'}, status=429)
#         messages.error(request, "Too many OTP requests. Try later.")
#         return redirect('core:login')

#     # Create and send OTP
#     create_mobile_otp_and_send(user, purpose='LOGIN')

#     if is_ajax(request):
#         return JsonResponse({'ok': True, 'message': 'OTP resent.'})
#     messages.success(request, "OTP resent. Check your phone.")
#     return redirect('core:login')


# dashboard page
# core/views.py
import json
import hmac
import hashlib
from decimal import Decimal

from django.shortcuts import render, redirect, get_object_or_404
from django.conf import settings
from django.http import JsonResponse, HttpResponseBadRequest, HttpResponse
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from django.urls import reverse
from django.utils import timezone
import django.db.models as models

import razorpay

from .models import Transaction, Notification
from .forms import RegistrationForm  # you already have forms; used only if needed

# Razorpay client (test)
razorpay_client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))


@login_required
def dashboard_view(request):
    user = request.user
    # basic aggregates
    recent_txns = user.transactions.order_by('-created_at')[:10]
    total_sent = user.transactions.filter(status=Transaction.STATUS_SUCCESS).aggregate(
        total=models.Sum('amount'))['total'] or Decimal('0.00')
    logger.info("asd")
    logger.info(settings.RAZORPAY_KEY_ID)
    context = {
        'user': user,
        'recent_txns': recent_txns,
        'total_sent': total_sent,
        'razorpay_key_id': settings.RAZORPAY_KEY_ID,
    }
    return render(request, 'core/dashboard.html', context)



# views.py (top)
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseBadRequest, JsonResponse
from decimal import Decimal
import razorpay
# ... other imports ...


def create_order_razor_view(request):
    logger.info('hey')
    if request.method != 'POST':
        return HttpResponseBadRequest("POST required")

    try:
        data = request.POST
        amount = Decimal(data.get('amount'))
        to_upi = data.get('to_upi', '').strip() or None
        provider_pref = data.get('provider', '').strip() or None
    except Exception:
        return JsonResponse({'ok': False, 'message': 'Invalid data'}, status=400)

    if amount <= 0:
        return JsonResponse({'ok': False, 'message': 'Amount must be positive'}, status=400)

    # safe: request.user is guaranteed to be a real User here
    txn = Transaction.objects.create(
        user=request.user,
        amount=amount,
        to_upi=to_upi,
        provider=provider_pref,
        status=Transaction.STATUS_PENDING
    )

    amount_paise = int(amount * Decimal('100'))
    try:
        razor_order = razorpay_client.order.create({
            'amount': amount_paise,
            'currency': 'INR',
            'receipt': f"txn_{txn.id}",
            'payment_capture': 1,
        })
    except Exception as e:
        txn.mark_failed(reason=str(e))
        return JsonResponse({'ok': False, 'message': 'Razorpay order creation failed', 'detail': str(e)}, status=500)

    txn.razorpay_order_id = razor_order.get('id')
    txn.save(update_fields=['razorpay_order_id'])

    return JsonResponse({
        'ok': True,
        'order_id': razor_order.get('id'),
        'txn_id': txn.id,
        'amount_paise': amount_paise
    })



@login_required
def verify_payment_view(request):
    """
    Called by frontend after Razorpay checkout success.
    Expects POST JSON: {razorpay_payment_id, razorpay_order_id, razorpay_signature, txn_id}
    Verifies signature and updates Transaction.
    """
    if request.method != 'POST':
        return HttpResponseBadRequest("POST required")

    razorpay_payment_id = request.POST.get('razorpay_payment_id')
    razorpay_order_id = request.POST.get('razorpay_order_id')
    razorpay_signature = request.POST.get('razorpay_signature')
    txn_id = request.POST.get('txn_id')

    if not (razorpay_payment_id and razorpay_order_id and razorpay_signature and txn_id):
        return JsonResponse({'ok': False, 'message': 'Missing parameters'}, status=400)

    txn = get_object_or_404(Transaction, pk=txn_id, user=request.user)

    # verify signature: hmac_sha256(order_id + "|" + payment_id, secret) == signature
    msg = f"{razorpay_order_id}|{razorpay_payment_id}".encode('utf-8')
    expected = hmac.new(settings.RAZORPAY_KEY_SECRET.encode('utf-8'), msg, hashlib.sha256).hexdigest()
    if expected != razorpay_signature:
        txn.mark_failed(reason='Signature mismatch')
        return JsonResponse({'ok': False, 'message': 'Signature verification failed'}, status=400)

    # optionally call Razorpay API to fetch payment details and confirm status
    try:
        payment = razorpay_client.payment.fetch(razorpay_payment_id)
    except Exception as e:
        txn.mark_failed(reason=str(e))
        return JsonResponse({'ok': False, 'message': 'Failed to fetch payment from Razorpay'}, status=500)

    # check captured status
    if payment.get('status') == 'captured':
        txn.mark_success(payment_id=razorpay_payment_id, signature=razorpay_signature)
        # add notification
        Notification.objects.create(user=request.user, message=f"Payment of ₹{txn.amount} successful (Payment ID {razorpay_payment_id}).")
        # optionally send SMS/email here using Twilio/email functions you already have
        return JsonResponse({'ok': True, 'message': 'Payment verified', 'txn_id': txn.id})
    else:
        txn.mark_failed(reason=f"Razorpay payment status: {payment.get('status')}")
        return JsonResponse({'ok': False, 'message': 'Payment not captured'}, status=400)


@csrf_exempt
def razorpay_webhook(request):
    """
    Webhook endpoint for Razorpay. Configure this URL in Razorpay dashboard webhook settings.
    Verify signature header 'X-Razorpay-Signature'.
    This updates transactions to success/failed as events arrive.
    """
    payload = request.body
    sig = request.META.get('HTTP_X_RAZORPAY_SIGNATURE', '')

    # Verify using HMAC SHA256 of payload with secret
    expected_sig = hmac.new(settings.RAZORPAY_KEY_SECRET.encode('utf-8'), payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_sig, sig):
        return HttpResponse(status=400)

    event = json.loads(payload.decode('utf-8'))
    # Example event handling
    event_type = event.get('event')
    data = event.get('payload', {})

    # handle payment captured
    if event_type == 'payment.captured':
        payment_entity = data.get('payment', {}).get('entity', {})
        razorpay_payment_id = payment_entity.get('id')
        razorpay_order_id = payment_entity.get('order_id')
        amount = payment_entity.get('amount')  # paise

        # find transaction by order id
        txn = Transaction.objects.filter(razorpay_order_id=razorpay_order_id).first()
        if txn:
            txn.mark_success(payment_id=razorpay_payment_id)
            Notification.objects.create(user=txn.user, message=f"Payment of ₹{txn.amount} succeeded via webhook.")
    elif event_type == 'payment.failed':
        payment_entity = data.get('payment', {}).get('entity', {})
        razorpay_order_id = payment_entity.get('order_id')
        reason = payment_entity.get('error_description') or 'payment failed'
        txn = Transaction.objects.filter(razorpay_order_id=razorpay_order_id).first()
        if txn:
            txn.mark_failed(reason=reason)
            Notification.objects.create(user=txn.user, message=f"Payment failed: {reason}")

    return HttpResponse(status=200)


import json
import hmac
import hashlib
from decimal import Decimal, InvalidOperation

from django.http import JsonResponse, HttpResponseBadRequest
from django.contrib.auth.decorators import login_required

# --- helper to safely mark a transaction failed without raising ---
def _safe_mark_failed(txn, reason):
    """
    Try to call txn.mark_failed(reason=...), otherwise set a status field
    and save gracefully. Prevents error-paths from raising secondary exceptions.
    """
    try:
        if hasattr(txn, 'mark_failed'):
            txn.mark_failed(reason=str(reason))
            return
    except Exception:
        # swallow and try fallback below
        pass

    try:
        # best-effort fallback updates
        if hasattr(txn, 'status'):
            failed_val = getattr(txn.__class__, 'STATUS_FAILED', None)
            txn.status = failed_val if failed_val is not None else 'failed'
        if hasattr(txn, 'failure_reason'):
            txn.failure_reason = str(reason)
        elif hasattr(txn, 'failure_note'):
            txn.failure_note = str(reason)
        try:
            txn.save()
        except Exception:
            pass
    except Exception:
        pass



def create_order_view(request):
    logger.info(request.user)
    """
    AJAX endpoint to create a Transaction (PENDING) and (optionally) a Razorpay Order.
    Expects POST: { amount: '500.00', to_upi: 'name@upi', provider: 'gpay'|'razorpay' }
    Returns JSON: { ok: True, order_id: 'order_xxx' or null, txn_id: <id>, amount_paise: 50000 }
    """

    if request.method != 'POST':
        return HttpResponseBadRequest("POST required")

    # Parse + validate inputs
    try:
        data = request.POST
        raw_amount = data.get('amount')
        if raw_amount is None:
            return JsonResponse({'ok': False, 'message': 'Missing amount'}, status=400)
        try:
            amount = Decimal(raw_amount)
        except (InvalidOperation, TypeError, ValueError):
            return JsonResponse({'ok': False, 'message': 'Invalid amount'}, status=400)

        to_upi = data.get('to_upi', '').strip() or None
        provider_pref = (data.get('provider', '') or '').strip().lower() or None
        txn_num = request.POST.get('txn_num')
    except Exception:
        return JsonResponse({'ok': False, 'message': 'Invalid data'}, status=400)

    if amount <= 0:
        return JsonResponse({'ok': False, 'message': 'Amount must be positive'}, status=400)

    # create local Transaction (PENDING)
    txn = Transaction.objects.create(
        user=request.user,
        amount=amount,
        to_upi=to_upi,
        provider=provider_pref,
        status=Transaction.STATUS_PENDING,
        txn_num=txn_num or None
    )

    # amount in paise
    amount_paise = int(amount * 100)


    # For UPI-app providers (gpay, phonepe, bhim, or unspecified), do NOT call Razorpay.
    # Return txn info so frontend can open intent or show QR (upi:// or intent://)
    return JsonResponse({
        'ok': True,
        'order_id': None,
        'txn_id': txn.txn_num or txn.id,
        'amount_paise': amount_paise
    })

from django.core.mail import send_mail

@require_POST
def i_paid(request):
    """
    Confirm payment by txn_num sent from browser localStorage.
    Expects JSON body: {"txn_num": "TXN..."}
    """
    try:
        payload = json.loads(request.body.decode('utf-8'))
        txn_num = payload.get('txn_numb')
    except Exception:
        return JsonResponse({'ok': False, 'message': 'Invalid request'}, status=400)

    if not txn_num:
        return JsonResponse({'ok': False, 'message': 'Missing txn_num'}, status=400)

    try:
        txn = Transaction.objects.get(user=request.user, txn_num=txn_num, status='PENDING')
    except Transaction.DoesNotExist:
        return JsonResponse({'ok': False, 'message': 'Transaction not found or already processed'}, status=404)

    # mark paid
    txn.status = Transaction.STATUS_SUCCESS if hasattr(Transaction, 'STATUS_SUCCESS') else 'PAID'
    txn.save(update_fields=['status', 'updated_at'])

    # send email (customize recipients)
    try:
        logger.info(settings.DEFAULT_FROM_EMAIL)
        logger.info(settings.DEFAULT_NOTIFICATION_EMAIL)
        logger.info(settings.EMAIL_HOST_PASSWORD)
        logger.info(settings.EMAIL_HOST_USER)
        subject=f'Payment received: {txn.txn_num} — ₹{txn.amount}'
        message=f'User {request.user} confirmed payment for {txn.to_upi}. Txn: {txn.txn_num}'
        logger.info(subject)
        logger.info(message)
        res = send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[settings.DEFAULT_NOTIFICATION_EMAIL],   # send to yourself to verify
            fail_silently=False,
        )
    except Exception as e:
        # email failure does not prevent success; report it optionally
        return JsonResponse({'ok': False, 'message': 'Marked paid but failed to send email', 'error': str(e)}, status=500)

    return JsonResponse({'ok': True, 'message': 'Marked paid'})


@login_required
def verify_payment_view(request):
    """
    Called by frontend after Razorpay checkout success.
    Expects POST JSON: {razorpay_payment_id, razorpay_order_id, razorpay_signature, txn_id}
    Verifies signature and updates Transaction.
    """
    if request.method != 'POST':
        return HttpResponseBadRequest("POST required")

    razorpay_payment_id = request.POST.get('razorpay_payment_id')
    razorpay_order_id = request.POST.get('razorpay_order_id')
    razorpay_signature = request.POST.get('razorpay_signature')
    txn_id = request.POST.get('txn_id')

    if not (razorpay_payment_id and razorpay_order_id and razorpay_signature and txn_id):
        return JsonResponse({'ok': False, 'message': 'Missing parameters'}, status=400)

    txn = get_object_or_404(Transaction, pk=txn_id, user=request.user)

    # verify signature: hmac_sha256(order_id + "|" + payment_id, secret) == signature
    try:
        msg = f"{razorpay_order_id}|{razorpay_payment_id}".encode('utf-8')
        expected = hmac.new(settings.RAZORPAY_KEY_SECRET.encode('utf-8'), msg, hashlib.sha256).hexdigest()
    except Exception:
        _safe_mark_failed(txn, 'Signature verification setup error')
        return JsonResponse({'ok': False, 'message': 'Signature verification failed'}, status=400)

    if expected != razorpay_signature:
        _safe_mark_failed(txn, 'Signature mismatch')
        return JsonResponse({'ok': False, 'message': 'Signature verification failed'}, status=400)

    # optionally call Razorpay API to fetch payment details and confirm status
    try:
        payment = razorpay_client.payment.fetch(razorpay_payment_id)
    except Exception as e:
        _safe_mark_failed(txn, str(e))
        return JsonResponse({'ok': False, 'message': 'Failed to fetch payment from Razorpay'}, status=500)

    # check captured status
    if payment.get('status') == 'captured':
        try:
            txn.mark_success(payment_id=razorpay_payment_id, signature=razorpay_signature)
        except Exception:
            # fallback if mark_success doesn't exist
            try:
                txn.status = getattr(Transaction, 'STATUS_SUCCESS', 'success')
                txn.save()
            except Exception:
                pass

        # add notification
        try:
            Notification.objects.create(user=request.user, message=f"Payment of ₹{txn.amount} successful (Payment ID {razorpay_payment_id}).")
        except Exception:
            pass

        return JsonResponse({'ok': True, 'message': 'Payment verified', 'txn_id': txn.id})
    else:
        _safe_mark_failed(txn, f"Razorpay payment status: {payment.get('status')}")
        return JsonResponse({'ok': False, 'message': 'Payment not captured'}, status=400)


@csrf_exempt
def razorpay_webhook(request):
    """
    Webhook endpoint for Razorpay. Configure this URL in Razorpay dashboard webhook settings.
    Verify signature header 'X-Razorpay-Signature'.
    This updates transactions to success/failed as events arrive.
    """
    payload = request.body
    sig = request.META.get('HTTP_X_RAZORPAY_SIGNATURE', '')

    # Verify using HMAC SHA256 of payload with secret
    try:
        expected_sig = hmac.new(settings.RAZORPAY_KEY_SECRET.encode('utf-8'), payload, hashlib.sha256).hexdigest()
    except Exception:
        return HttpResponse(status=400)

    if not hmac.compare_digest(expected_sig, sig):
        return HttpResponse(status=400)

    try:
        event = json.loads(payload.decode('utf-8'))
    except Exception:
        return HttpResponse(status=400)

    event_type = event.get('event')
    data = event.get('payload', {})

    # handle payment captured
    if event_type == 'payment.captured':
        payment_entity = data.get('payment', {}).get('entity', {})
        razorpay_payment_id = payment_entity.get('id')
        razorpay_order_id = payment_entity.get('order_id')
        amount = payment_entity.get('amount')  # paise

        # find transaction by order id
        txn = Transaction.objects.filter(razorpay_order_id=razorpay_order_id).first()
        if txn:
            try:
                txn.mark_success(payment_id=razorpay_payment_id)
            except Exception:
                try:
                    txn.status = getattr(Transaction, 'STATUS_SUCCESS', 'success')
                    txn.save()
                except Exception:
                    pass
            try:
                Notification.objects.create(user=txn.user, message=f"Payment of ₹{txn.amount} succeeded via webhook.")
            except Exception:
                pass

    elif event_type == 'payment.failed':
        payment_entity = data.get('payment', {}).get('entity', {})
        razorpay_order_id = payment_entity.get('order_id')
        reason = payment_entity.get('error_description') or 'payment failed'
        txn = Transaction.objects.filter(razorpay_order_id=razorpay_order_id).first()
        if txn:
            _safe_mark_failed(txn, reason)
            try:
                Notification.objects.create(user=txn.user, message=f"Payment failed: {reason}")
            except Exception:
                pass

    return HttpResponse(status=200)


# recharge
import json
from decimal import Decimal
from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse
from django.conf import settings
from django.http import JsonResponse, HttpResponseBadRequest
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import ensure_csrf_cookie
from .models import Operator, RechargePlan, RechargeOrder

# ---------------- Dashboard ----------------
def dashboard_view(request):
    operators = Operator.objects.all()[:6]
    recent = RechargeOrder.objects.order_by('-created_at')[:6]
    return render(request, "core/dashboard.html", {"operators": operators, "recent": recent,'razorpay_key_id': settings.RAZORPAY_KEY_ID})


# ---------------- Recharge page ----------------
def recharge_view(request):
    operators = Operator.objects.all().order_by("name")
    return render(request, "core/recharge.html", {"operators": operators})

# ---------------- Plans API (AJAX) ----------------
def api_get_plans(request, operator_code):
    try:
        op = Operator.objects.get(code=operator_code)
    except Operator.DoesNotExist:
        return JsonResponse({"ok": False, "error": "Operator not found"}, status=404)

    plans_qs = op.plans.all()
    if plans_qs.exists():
        plans = [{"id": p.id, "title": p.title, "amount": float(p.amount), "validity": p.validity, "desc": p.description} for p in plans_qs]
        return JsonResponse({"ok": True, "plans": plans})
    else:
        # Fallback mock plans (replace with provider call if you prefer)
        mock = [
            {"id": "P100", "title": "Talktime - ₹49", "amount": 49.00, "validity": "NA", "desc": "Instant talktime"},
            {"id": "P200", "title": "Data - ₹99", "amount": 99.00, "validity": "28 days", "desc": "1GB/day pack"},
            {"id": "P300", "title": "Full plan - ₹199", "amount": 199.00, "validity": "56 days", "desc": "Data + calls"},
        ]
        return JsonResponse({"ok": True, "plans": mock})

# ---------------- Create order and redirect to UPI page ----------------
@require_POST
def create_recharge(request):
    mobile = request.POST.get("mobile", "").strip()
    operator_code = request.POST.get("operator")
    plan_id = request.POST.get("plan_id")
    amount = request.POST.get("amount")

    if not mobile or not amount:
        return HttpResponseBadRequest("mobile and amount are required")

    try:
        amount_val = Decimal(amount)
        if amount_val <= 0:
            return HttpResponseBadRequest("invalid amount")
    except:
        return HttpResponseBadRequest("invalid amount format")

    operator = Operator.objects.filter(code=operator_code).first() if operator_code else None
    plan = RechargePlan.objects.filter(pk=plan_id).first() if plan_id else None

    order = RechargeOrder.objects.create(
        user=request.user if request.user.is_authenticated else None,
        mobile=mobile,
        operator=operator,
        plan=plan,
        amount=amount_val,
        status="INITIATED"
    )

    return redirect(reverse("core:recharge_upi_page", kwargs={"order_id": order.id}))

# ---------------- UPI page (GET shows page; POST used by AJAX to submit TXN id) ----------------
@ensure_csrf_cookie
def recharge_upi_page(request, order_id):
    order = get_object_or_404(RechargeOrder, pk=order_id)

    if request.method == "POST":
        # Accept JSON { upi_tid: "..." } from frontend
        try:
            data = json.loads(request.body.decode())
            tid = data.get("upi_tid")
            if not tid:
                return JsonResponse({"ok": False, "error": "No tid provided"}, status=400)
            # Save tid and mark as PAID
            order.upi_tid = tid
            order.status = "PAID"
            order.save()
            # Immediately call provider to perform recharge (mocked)
            provider_resp = call_recharge_provider(order)
            # Update based on provider response
            if provider_resp.get("status") == "SUCCESS":
                order.status = "SUCCESS"
                order.provider_txn = provider_resp.get("provider_txn", "")
            elif provider_resp.get("status") == "FAILED":
                order.status = "FAILED"
                order.notes = provider_resp.get("message", "")
            else:
                order.status = "PROCESSING"
                order.provider_txn = provider_resp.get("provider_txn", "")
                order.notes = provider_resp.get("message", "")
            order.save()
            return JsonResponse({"ok": True, "provider": provider_resp})
        except Exception as e:
            return JsonResponse({"ok": False, "error": str(e)}, status=400)

    # GET: build upi params for front-end to open
    upi_vpa = getattr(settings, "MERCHANT_UPI", "yourmerchant@bank")
    upi_name = getattr(settings, "MERCHANT_NAME", "GapyPay")
    note = f"Recharge {order.mobile} order:{order.id}"
    upi_params = {
        "pa": upi_vpa,
        "pn": upi_name,
        "am": str(order.amount),
        "tn": note,
        "tid": str(order.id),
        "cu": "INR",
    }
    return render(request, "core/recharge_upi_page.html", {"order": order, "upi_params": upi_params})

# ---------------- Submit TXN via regular POST fallback (form submit) ----------------
@require_POST
def submit_upi_tid(request, order_id):
    order = get_object_or_404(RechargeOrder, pk=order_id)
    tid = request.POST.get("upi_tid", "").strip()
    if not tid:
        return redirect(reverse("core:recharge_upi_page", kwargs={"order_id": order.id}))
    order.upi_tid = tid
    order.status = "PAID"
    order.save()
    provider_resp = call_recharge_provider(order)
    if provider_resp.get("status") == "SUCCESS":
        order.status = "SUCCESS"
        order.provider_txn = provider_resp.get("provider_txn", "")
    elif provider_resp.get("status") == "FAILED":
        order.status = "FAILED"
        order.notes = provider_resp.get("message", "")
    else:
        order.status = "PROCESSING"
        order.provider_txn = provider_resp.get("provider_txn", "")
    order.save()
    return redirect(reverse("core:recharge_upi_page", kwargs={"order_id": order.id}))

# ---------------- Mock provider call ----------------
def call_recharge_provider(order: RechargeOrder):
    """
    Replace this with real provider integration. For Option 1 you still need
    a recharge provider (Roundpay/Scriza/A1Topup) to actually perform the recharge.
    This mock simulates success/failure.
    """
    try:
        import random, time
        time.sleep(0.4)
        outcome = random.choices(["SUCCESS", "PROCESSING", "FAILED"], weights=[0.75, 0.18, 0.07], k=1)[0]
        provider_txn = f"MOCK{random.randint(111111,999999)}"
        return {"status": outcome, "provider_txn": provider_txn, "message": "Mock response"}
    except Exception as e:
        return {"status": "PROCESSING", "provider_txn": "", "message": str(e)}


from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from .models import Transaction

# @login_required
# def transactions_view(request):
#     """
#     Render dashboard with recent transactions for the logged-in user.
#     Shows the latest 20 by default.
#     """
#     logger.info(2)
#     recent_txns = (
#         Transaction.objects
#         .filter(user=request.user)
#         .order_by('-created_at')[:20]   # latest first, limit 20
#     )
#     if request.headers.get('x-requested-with') == 'XMLHttpRequest':
#         data = [
#             {
#                 "date": t.created_at.strftime("%b %d, %H:%M"),
#                 "to": t.to_upi or "-",
#                 "amount": float(t.amount),
#                 "provider": t.provider or "-",
#                 "status": t.status,
#             }
#             for t in recent_txns
#         ]
#         return JsonResponse({"ok": True, "transactions": data})
#     logger.info(recent_txns)
#     return render(request, "core/dashboard.html", {
#         'recent_txns': recent_txns
#     })

from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import render
from .models import Transaction
from django.urls import reverse

@login_required
def transactions_view(request):
    """
    Render dashboard with recent transactions for the logged-in user.
    Shows the latest 20 by default. If the request is AJAX, return JSON.
    """
    recent_txns = (
        Transaction.objects
        .filter(user=request.user)
        .order_by('-created_at')[:20]   # latest first, limit 20
    )

    # Robust AJAX detection
    if request.headers.get('x-requested-with', '').lower() == 'xmlhttprequest':
        data = []
        for t in recent_txns:
            # Build a minimal retry_url if you want to surface an action for pending txns.
            # Example: if provider is 'razorpay' you might link back to a retry/pay page.
            retry_url = ''
            # if t.status.lower() == 'pending' and t.provider == 'razorpay':
            #     retry_url = reverse('core:retry_payment', args=[t.id])

            data.append({
                'id': t.id,                              # stable numeric id (used to fetch detail)
                'txn_num': getattr(t, 'txn_num', '') or '',  # optional fallback token
                'date': t.created_at.strftime("%b %d, %H:%M"),
                'to': t.to_upi or getattr(t, 'to', '-') or '-',
                'amount': float(t.amount or 0),
                'provider': t.provider or '-',
                'status': t.status or '-',
                'retry_url': retry_url,
                
            })
        return JsonResponse({"ok": True, "transactions": data})

    # Non-AJAX (normal page render)
    return render(request, "core/dashboard.html", {
        'recent_txns': recent_txns
    })


# transdetails
from django.http import JsonResponse, Http404
from django.contrib.auth.decorators import login_required
from .models import Transaction

@login_required
def transaction_detail(request, txn_id):
    # Accept AJAX only ideally
    try:
        txn = Transaction.objects.get(id=txn_id, user=request.user)
    except Transaction.DoesNotExist:
        raise Http404("Transaction not found")

    # Build timeline list (example; adapt to your model fields)
    timeline = []
    timeline.append({'event': 'Created', 'at': txn.created_at.isoformat()})
    if txn.qr_generated_at: timeline.append({'event':'QR Generated','at': txn.qr_generated_at.isoformat()})
    if txn.i_paid_at: timeline.append({'event':'I-Paid Submitted','at': txn.i_paid_at.isoformat()})
    if txn.razorpay_paid_at: timeline.append({'event':'Razorpay Paid','at': txn.razorpay_paid_at.isoformat()})
    # More events...

    data = {
        'id': txn.id,
        'txn_num': txn.txn_num,
        'to': txn.to_upi,
        'amount': float(txn.amount),
        'status': txn.status,
        'provider': txn.provider,
        'created_at': txn.created_at.strftime('%Y-%m-%d %H:%M:%S %Z'),
        'razorpay_order_id': txn.razorpay_order_id,
        'razorpay_payment_id': txn.razorpay_payment_id,
        'upi_reference': txn.upi_reference,
        'timeline': timeline,
        # raw payloads if you store them
        'raw_payload': txn.raw_payload or {},
        # optional action link for pending payments (retry) or recharge page
        'retry_url': txn.get_retry_url() if hasattr(txn,'get_retry_url') else '',
        'qr_generated_at': txn.qr_generated_at and txn.qr_generated_at.strftime('%Y-%m-%d %H:%M:%S') or '',
'i_paid_at': txn.i_paid_at and txn.i_paid_at.strftime('%Y-%m-%d %H:%M:%S') or '',
'razorpay_paid_at': txn.razorpay_paid_at and txn.razorpay_paid_at.strftime('%Y-%m-%d %H:%M:%S') or '',
'verified_at': txn.verified_at and txn.verified_at.strftime('%Y-%m-%d %H:%M:%S') or '',
'upi_reference': txn.upi_reference or '',
'raw_payload': txn.raw_payload or {},
'retry_url': txn.get_retry_url(),
    }
    return JsonResponse({'ok': True, 'transaction': data})

# from django.http import HttpResponse
# from reportlab.pdfgen import canvas

# @login_required
# def transaction_pdf(request, txn_id):
#     txn = Transaction.objects.get(id=txn_id, user=request.user)
#     response = HttpResponse(content_type='application/pdf')
#     response['Content-Disposition'] = f'attachment; filename="{txn.txn_num}.pdf"'
#     p = canvas.Canvas(response)
#     p.drawString(100,800, f"GapyPay - Receipt")
#     p.drawString(100,780, f"Txn: {txn.txn_num}")
#     p.drawString(100,760, f"Amount: ₹{txn.amount}")
#     # add more...
#     p.showPage()
#     p.save()
#     return response

from django.shortcuts import render
from django.contrib.auth.decorators import login_required

@login_required
def transaction_stats(request):
    # page loads, the JS will fetch actual transactions via your existing AJAX view
    return render(request, 'core/txn_stats.html')