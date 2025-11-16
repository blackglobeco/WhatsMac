import geoip2.database
import os

# Download the MaxMind GeoLite2 database and provide its path
# Default location for macOS - adjust as needed
# GEO_DB_PATH = os.path.expanduser("~/GeoLite2-City.mmdb")

# Alternative: Place in project directory
GEO_DB_PATH = os.path.join(os.path.dirname(__file__), "..", "GeoLite2-City.mmdb")

def get_geo_info(ip):
    """
    Get geolocation information for an IP address.
    
    Note: You need to download GeoLite2-City.mmdb from:
    https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
    """
    if not os.path.exists(GEO_DB_PATH):
        print(f"[-] GeoIP database not found at: {GEO_DB_PATH}")
        print(f"[-] Download from: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data")
        return None
    
    try:
        with geoip2.database.Reader(GEO_DB_PATH) as reader:
            response = reader.city(ip)
            return {
                "ip": ip,
                "country": response.country.name or "Unknown",
                "city": response.city.name or "Unknown",
                "latitude": response.location.latitude,
                "longitude": response.location.longitude
            }
    except geoip2.errors.AddressNotFoundError:
        print(f"[-] No geolocation data found for IP: {ip}")
        return None
    except Exception as e:
        print(f"[-] Error fetching geolocation for {ip}: {e}")
        return None
