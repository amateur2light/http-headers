```bash
#!/bin/bash

# Define colors
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'

# List of OWASP security headers
owasp_headers=("Content-Security-Policy" "Strict-Transport-Security" "X-Content-Type-Options" "X-Frame-Options" "Referrer-Policy" "X-Permitted-Cross-Domain-Policies" "Clear-Site-Data" "Cross-Origin-Embedder-Policy" "Cross-Origin-Opener-Policy" "Cross-Origin-Resource-Policy" "Cache-Control")

# Define a function to check if a given header is present
function check_header {
    local header=$1
    local header_value=$(curl -I -s "$url" | grep -i "^$header" | awk -F': ' '{print $2}')
    if [[ -n "$header_value" ]]; then
        present_headers+=("• $header: $header_value")
    else
        missing_headers+=("• $header")
    fi
}

# Prompt user to enter a URL to check
read -p "Enter the URL to check for missing OWASP headers: " url

# Check if the entered URL starts with "http://" or "https://"
if [[ ! $url =~ ^https?:// ]]
then
  echo -e "${RED}Invalid URL. Please enter a URL starting with 'http://' or 'https://'${NC}"
  exit 1
fi

# Extract the domain from the entered URL
DOMAIN=$(echo "$url" | awk -F[/:] '{print $4}')

# Check if the domain is valid
if ! ping -c 1 -W 1 "$DOMAIN" > /dev/null 2>&1
then
  echo -e "${RED}Invalid domain. Please enter a valid domain.${NC}"
  exit 1
fi

# Get the response headers for the entered URL
ENTERED_HEADERS=$(curl -s -I -X GET "$url")

# Initialize arrays for missing and present headers for original URL
missing_headers=()
present_headers=()

# Check for headers on the provided URL
echo "Checking for OWASP headers on $url..."
for header in "${owasp_headers[@]}"; do
    check_header "$header"
done

# Initialize arrays for missing and present headers for redirected URL (if any)
redirected=false
missing_headers_redirect=()
present_headers_redirect=()

# Check for redirected URL
http_status=$(curl -o /dev/null -I -s -w "%{http_code}\n" "$url")
if [[ "$http_status" -ge 300 && "$http_status" -lt 400 ]]; then
    redirected=true
    redirected_url=$(curl -L -s -o /dev/null -w '%{url_effective}' "$url")
    read -p "Do you want to check for OWASP headers on the redirected URL? (y/n) " check_redirect
    if [[ "$check_redirect" == "y" || "$check_redirect" == "yes" ]]; then
        echo "URL is redirecting to $redirected_url"
        echo "Checking for OWASP headers on $redirected_url..."
        # Check for headers on the redirected URL
        for header in "${owasp_headers[@]}"; do
            header_value=$(curl -I -s "$redirected_url" | grep -i "^$header" | awk -F': ' '{print $2}')
            if [[ -n "$header_value" ]]; then
                present_headers_redirect+=("• $header: $header_value")
            else
                missing_headers_redirect+=("• $header")
            fi
        done
    fi
fi

# Print results for original URL
echo ""
echo "Results for $url:"
echo "------------------"
echo "Missing headers:"
printf "%s\n" "${missing_headers[@]}"
echo ""
echo "Present headers:"
printf "%s\n" "${present_headers[@]}"

# Print results for redirected URL (if any)
if [[ "$redirected" == true ]]; then
    echo ""
    echo "Results for $redirected_url:"
    echo "---------------------------"
    echo "Missing headers:"
    printf "%s\n" "${missing_headers_redirect[@]}"
    echo ""
    echo "Present headers:"
    printf "%s\n" "${present_headers_redirect[@]}"
fi
echo ""
echo "For best security practices refer : https://owasp.org/www-project-secure-headers/#x-permitted-cross-domain-policies"
```