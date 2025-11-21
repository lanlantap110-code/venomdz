from flask import Flask, jsonify, request
import requests
import logging
from functools import wraps
import time

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def make_request(url, headers=None, timeout=10):
    """Helper function to make HTTP requests with error handling"""
    try:
        response = requests.get(url, headers=headers, timeout=timeout)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"Request failed: {e}")
        return None

@app.route('/')
def home():
    return jsonify({
        'message': 'VenomDz API Server',
        'endpoints': {
            '/phonenumberinfo/<number>': 'Get phone number information',
            '/vehicleinfo/<number>': 'Get vehicle information', 
            '/ipinfo/<ip>': 'Get IP address information',
            '/aadhharinfo/<aadhaar>': 'Get Aadhaar information',
            '/phishcheck/<path:url>': 'Check URL for phishing',
            '/iplocation/<ip>': 'Get IP geolocation',
            '/allinfo/phone/<number>': 'Get complete phone number info with multiple sources',
            '/allinfo/ip/<ip>': 'Get complete IP info with multiple sources'
        },
        'status': 'active'
    })

@app.route('/phonenumberinfo/<number>')
def phone_number_info(number):
    """
    Get phone number information
    Example: /phonenumberinfo/9876543210
    """
    if not number.isdigit() or len(number) != 10:
        return jsonify({'error': 'Invalid phone number format. Must be 10 digits.'}), 400
    
    try:
        api_url = f"https://splexxo-info.vercel.app/api/seller?mobile={number}&key=SPLEXXO"
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
        logger.error(f"Phone number lookup error: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/vehicleinfo/<vehicle_number>')
def vehicle_info(vehicle_number):
    """
    Get vehicle information by registration number
    Example: /vehicleinfo/RJ14CY0002
    """
    try:
        # Clean and validate vehicle number
        vehicle_number = vehicle_number.upper().strip()
        
        # Use CORS proxy
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

@app.route('/ipinfo/<ip>')
def ip_info(ip):
    """
    Get IP address information
    Example: /ipinfo/192.168.1.1
    """
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

@app.route('/aadhharinfo/<aadhaar>')
def aadhaar_info(aadhaar):
    """
    Get Aadhaar information
    Example: /aadhharinfo/123456789012
    """
    if not aadhaar.isdigit() or len(aadhaar) != 12:
        return jsonify({'error': 'Invalid Aadhaar number format. Must be 12 digits.'}), 400
    
    try:
        # Use CORS proxy for Aadhaar API
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

@app.route('/phishcheck/<path:url>')
def phish_check(url):
    """
    Check URL for phishing indicators
    Example: /phishcheck/https://example.com
    """
    try:
        # Add protocol if missing
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        # Basic phishing analysis
        analysis = {
            'url': url,
            'risk_score': 0,
            'risk_level': 'LOW',
            'threats': [],
            'recommendation': 'This link appears to be safe'
        }
        
        # Threat detection logic
        from urllib.parse import urlparse
        parsed_url = urlparse(url)
        
        # Check for suspicious domains
        suspicious_patterns = [
            'login-', 'verify-', 'security-', 'account-', 'update-',
            'confirm-', 'secure-', 'auth-', 'signin-', 'facebook',
            'google', 'microsoft', 'apple', 'amazon', 'paypal'
        ]
        
        hostname = parsed_url.hostname.lower()
        for pattern in suspicious_patterns:
            if pattern in hostname:
                analysis['threats'].append({
                    'type': 'SUSPICIOUS_DOMAIN',
                    'severity': 'HIGH',
                    'message': f'Domain contains suspicious pattern: {pattern}'
                })
                analysis['risk_score'] += 20
        
        # Check for IP address in hostname
        import re
        ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        if ip_pattern.match(hostname):
            analysis['threats'].append({
                'type': 'IP_ADDRESS_URL',
                'severity': 'MEDIUM',
                'message': 'URL uses IP address instead of domain name'
            })
            analysis['risk_score'] += 15
        
        # Check for HTTPS
        if parsed_url.scheme != 'https':
            analysis['threats'].append({
                'type': 'NO_HTTPS',
                'severity': 'MEDIUM',
                'message': 'Connection is not secure (HTTP instead of HTTPS)'
            })
            analysis['risk_score'] += 10
        
        # Check for excessive subdomains
        if hostname.count('.') > 3:
            analysis['threats'].append({
                'type': 'EXCESSIVE_SUBDOMAINS',
                'severity': 'LOW',
                'message': 'URL has excessive number of subdomains'
            })
            analysis['risk_score'] += 5
        
        # Check for suspicious ports
        if parsed_url.port and parsed_url.port not in [80, 443, 8080]:
            analysis['threats'].append({
                'type': 'SUSPICIOUS_PORT',
                'severity': 'MEDIUM',
                'message': f'URL uses non-standard port: {parsed_url.port}'
            })
            analysis['risk_score'] += 10
        
        # Determine risk level
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

@app.route('/iplocation/<ip>')
def ip_location(ip):
    """
    Get detailed IP geolocation
    Example: /iplocation/8.8.8.8
    """
    try:
        # Try multiple IP geolocation APIs
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
        logger.error(f"IP location error: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/allinfo/phone/<number>')
def all_phone_info(number):
    """
    Get comprehensive phone number information from multiple sources
    Example: /allinfo/phone/9876543210
    """
    if not number.isdigit() or len(number) != 10:
        return jsonify({'error': 'Invalid phone number format. Must be 10 digits.'}), 400
    
    try:
        results = {}
        
        # Source 1: Main API
        api_url = f"https://demon.taitanx.workers.dev/?mobile={number}"
        response = requests.get(api_url, timeout=10)
        if response.status_code == 200:
            results['main_source'] = response.json()
        
        # Source 2: Alternative lookup (you can add more sources here)
        # Add more phone lookup APIs as needed
        
        return jsonify({
            'success': True,
            'number': number,
            'sources_checked': len(results),
            'data': results
        })
        
    except Exception as e:
        logger.error(f"Comprehensive phone lookup error: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/allinfo/ip/<ip>')
def all_ip_info(ip):
    """
    Get comprehensive IP information from multiple sources
    Example: /allinfo/ip/8.8.8.8
    """
    try:
        results = {}
        
        # Source 1: FindIPInfo
        api1_url = f"https://findipinfo.net/api/ipinfo/5a39dc17447a439ae25a02c091e9d37b57253915?ip={ip}"
        response1 = requests.get(api1_url, timeout=10)
        if response1.status_code == 200:
            results['findipinfo'] = response1.json()
        
        # Source 2: ipapi.co
        api2_url = f"https://ipapi.co/{ip}/json/"
        response2 = requests.get(api2_url, timeout=8)
        if response2.status_code == 200:
            results['ipapi_co'] = response2.json()
        
        # Source 3: ip-api.com
        api3_url = f"http://ip-api.com/json/{ip}"
        response3 = requests.get(api3_url, timeout=8)
        if response3.status_code == 200:
            results['ip_api_com'] = response3.json()
        
        return jsonify({
            'success': True,
            'ip': ip,
            'sources_checked': len(results),
            'data': results
        })
        
    except Exception as e:
        logger.error(f"Comprehensive IP lookup error: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': time.time(),
        'service': 'VenomDz API Server',
        'version': '1.0.0'
    })

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({'error': 'Method not allowed'}), 405

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
