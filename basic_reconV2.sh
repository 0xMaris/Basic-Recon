#!/bin/bash

set -e  # Exit immediately if a command exits with a non-zero status

skip="true"
domain=""
target=""

# Function to check if a command exists
command_exists() {
  command -v "$1" >/dev/null 2>&1
}

# Function to log messages
log_message() {
  echo "$(date +"%Y-%m-%d %H:%M:%S") - $1"
}

# Check for required commands
for cmd in assetfinder subfinder wafw00f aquatone; do
  if ! command_exists "$cmd"; then
    echo "Error: $cmd is not installed."
    exit 1
  fi
done

# Parse command-line arguments
while getopts ":d:o:t:" opt; do
  case $opt in
    d)
      domain="$OPTARG"
      ;;
    o)
      out_of_scope_domains="$OPTARG"
      ;;
    t)
      target="$OPTARG"
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      exit 1
      ;;
    :)
      echo "Option -$OPTARG requires an argument." >&2
      exit 1
      ;;
  esac
done

if [ -z "$domain" ]; then
  echo "Domain name not provided."
  exit 1
fi

if [ -z "$target" ]; then
  echo "Target directory not provided."
  exit 1
fi

target_dir="$HOME/targets/$target/assets/$domain"

# Create target directory if it doesn't exist
mkdir -p "$target_dir"

log_file="$target_dir/script.log"
exec > >(tee -i $log_file) 2>&1  # Redirect stdout and stderr to the log file

log_message "Enumerating assets related to $domain"
assetfinder "$domain" > "$target_dir/$domain.txt"
log_message "Enumerating subdomains related to $domain"
subfinder -d "$domain" >> "$target_dir/$domain.txt"
log_message "Building target list"
sort "$target_dir/$domain.txt" | uniq > "$target_dir/sorted-$domain.txt"

# Handle out of scope domains
if [ -n "$out_of_scope_domains" ]; then
  IFS=',' read -ra out_of_scope_arr <<< "$out_of_scope_domains"
  for var in "${out_of_scope_arr[@]}"; do
    if [[ "$skip" == "false" ]]; then
      grep -v "$var" "$target_dir/sorted-$domain.txt" > tmpfile && mv tmpfile "$target_dir/sorted-$domain.txt"
      log_message "Out of scope domain $var has been removed from the target list."
    else
      skip="false"
    fi
  done
else
  log_message "No out of scope domains specified"
fi

lines=$(wc -l < "$target_dir/sorted-$domain.txt")
voicelines=$(wc -l < "$target_dir/sorted-$domain.txt" | sed ':a;s/\B[0-9]\{3\}\>/,&/;ta')

log_message "Checking for WAF protection"
wafw00f "$domain" > "$target_dir/waf-$domain.txt"

WAF=$(sed -n -e 's/^.*behind //p' "$target_dir/waf-$domain.txt" | tr -cd 'a-zA-Z ' | sed 's/\(.*\)m/\1/'| rev | sed 's/\(.*\)m/\1/'| rev | sed 's/WAF//')
if [[ $WAF ]]; then
  log_message "$domain is behind the $WAF web application firewall"
  seconds_per_subdomain=8
else
  log_message "$domain is not protected by a web application firewall"
  seconds_per_subdomain=4
fi

# Test a small subset of subdomains to estimate time
log_message "Testing a small subset of subdomains to estimate time"
test_subdomains=$(head -n 10 "$target_dir/sorted-$domain.txt")
start_time=$(date +%s)
echo "$test_subdomains" | aquatone > /dev/null 2>&1
end_time=$(date +%s)

elapsed_time=$((end_time - start_time))
average_time_per_subdomain=$((elapsed_time / 10))
estimated_time=$((average_time_per_subdomain * lines))

# Convert estimated time to hours, minutes, and seconds
hours=$((estimated_time / 3600))
minutes=$((estimated_time % 3600 / 60))
seconds=$((estimated_time % 60))
log_message "Starting initial recon on $voicelines subdomains. Estimated time to completion: $hours hours, $minutes minutes, and $seconds seconds."

cat "$target_dir/sorted-$domain.txt" | aquatone > "$target_dir/$domain-aquatone.txt"


goodreq=$(grep -m 1 "Successful" "$target_dir/$domain-aquatone.txt" | cut -d: -f2 | sed ':a;s/\B[0-9]\{3\}\>/,&/;ta')
goodpic=$(grep -m 2 "Successful" "$target_dir/$domain-aquatone.txt" | cut -d: -f2 | tail -n1 | sed ':a;s/\B[0-9]\{3\}\>/,&/;ta')
badreq=$(grep -m 1 " - Failed" "$target_dir/$domain-aquatone.txt" | cut -d: -f2 | sed ':a;s/\B[0-9]\{3\}\>/,&/;ta')
badpic=$(grep -m 2 " - Failed" "$target_dir/$domain-aquatone.txt" | cut -d: -f2 | tail -n1 | sed ':a;s/\B[0-9]\{3\}\>/,&/;ta')

log_message "Scan complete, $goodreq successful requests made, $badreq failed, $goodpic screenshots were taken, $badpic attempts failed, see report for details."

cp aquatone_report.html "$target_dir"

directories=(
    "$target_dir/headers"
    "$target_dir/html"
    "$target_dir/screenshots"
)

for dir in "${directories[@]}"; do
    if [ -d "$dir" ]; then
        log_message "Directory $dir exists. Removing..."
        rm -r "$dir"
    else
        log_message "Directory $dir does not exist. Creating it..."
    fi
done

mv -f headers "$target_dir"
mv -f html "$target_dir"
mv -f screenshots "$target_dir"
