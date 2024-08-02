#!/bin/bash

skip="true"
domain=""
target=""

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

# Create directories if they don't exist
mkdir -p "$HOME/targets/$target/assets/$domain"

echo "Enumerating assets related to $domain"
assetfinder "$domain" > "$HOME/targets/$target/assets/$domain/$domain.txt"
echo "Enumerating subdomains related to $domain"
subfinder -d "$domain" >> "$HOME/targets/$target/assets/$domain/$domain.txt"
echo "Building target list"
sort "$HOME/targets/$target/assets/$domain/$domain.txt" | uniq > "$HOME/targets/$target/assets/$domain/sorted-$domain.txt"

if [ -n "$out_of_scope_domains" ]; then
  IFS=',' read -ra out_of_scope_arr <<< "$out_of_scope_domains"
  for var in "${out_of_scope_arr[@]}"; do
    if [[ "$skip" == "false" ]]; then
      grep -v "$var" "$HOME/targets/$target/assets/$domain/sorted-$domain.txt" > tmpfile && mv tmpfile "$HOME/targets/$target/assets/$domain/sorted-$domain.txt"
      echo "Out of scope domain $var has been removed from the target list."
    else
      skip="false"
    fi
  done
else
  echo "No out of scope domains specified"
fi

lines=$(cat "$HOME/targets/$target/assets/$domain/sorted-$domain.txt" | wc -l)
formatted_lines=$(cat "$HOME/targets/$target/assets/$domain/sorted-$domain.txt" | wc -l | sed ':a;s/\B[0-9]\{3\}\>/,&/;ta')

wafw00f "$domain" > "$HOME/targets/$target/assets/$domain/waf-$domain.txt"

WAF=$(sed -n -e 's/^.*behind //p' "$HOME/targets/$target/assets/$domain/waf-$domain.txt" | tr -cd 'a-zA-Z ' | sed 's/\(.*\)m/\1/'| rev | sed 's/\(.*\)m/\1/'| rev | sed 's/WAF//')
if [[ $WAF ]]; then
  echo "$domain is behind the $WAF web application firewall"
  seconds=$((lines * 8))
else
  echo "$domain is not protected by a web application firewall"
  seconds=$((lines * 4))
fi

secs=$((seconds / 10))
hours=$((secs / 3600))
minutes=$((secs % 3600 / 60))
seconds=$((secs % 60))

echo "Starting initial recon on $formatted_lines subdomains. Estimated time to completion, $hours hours, $minutes minutes, and $seconds seconds."

cat "$HOME/targets/$target/assets/$domain/sorted-$domain.txt" | aquatone > "$HOME/targets/$target/assets/$domain/$domain-aquatone.txt"

goodreq=$(grep -m 1 "Successful" "$HOME/targets/$target/assets/$domain/$domain-aquatone.txt" | cut -d: -f2 | sed ':a;s/\B[0-9]\{3\}\>/,&/;ta')
goodpic=$(grep -m 2 "Successful" "$HOME/targets/$target/assets/$domain/$domain-aquatone.txt" | cut -d: -f2 | tail -n1 | sed ':a;s/\B[0-9]\{3\}\>/,&/;ta')
badreq=$(grep -m 1 " - Failed" "$HOME/targets/$target/assets/$domain/$domain-aquatone.txt" | cut -d: -f2 | sed ':a;s/\B[0-9]\{3\}\>/,&/;ta')
badpic=$(grep -m 2 " - Failed" "$HOME/targets/$target/assets/$domain/$domain-aquatone.txt" | cut -d: -f2 | tail -n1 | sed ':a;s/\B[0-9]\{3\}\>/,&/;ta')

echo "Scan complete, $goodreq successful requests made, $badreq failed, $goodpic screenshots were taken, $badpic attempts failed, see report for details."

cp aquatone_report.html "$HOME/targets/$target/assets/$domain"

directories=(
    "$HOME/targets/$target/assets/$domain/headers"
    "$HOME/targets/$target/assets/$domain/html"
    "$HOME/targets/$target/assets/$domain/screenshots"
)

for dir in "${directories[@]}"; do
    if [ -d "$dir" ]; then
        echo "Directory $dir exists. Removing..."
        rm -r "$dir"
    else
        echo "Directory $dir does not exist. Creating it..."
    fi
done

mv -f headers "$HOME/targets/$target/assets/$domain"
mv -f html "$HOME/targets/$target/assets/$domain"
mv -f screenshots "$HOME/targets/$target/assets/$domain"
