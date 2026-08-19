# Use a lightweight Nginx web server
FROM nginx:alpine

# Copy your frontend files (index.html, app.js, etc.) to the web server's public directory
COPY . /usr/share/nginx/html

# Expose port 80 for web traffic
EXPOSE 80

# Start Nginx
CMD ["nginx", "-g", "daemon off;"]