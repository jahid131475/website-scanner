
### File 3: `install.sh`
```bash
#!/bin/bash

echo "Installing Website Scanner..."
echo "Checking dependencies..."

# Check if nmap is installed
if ! command -v nmap &> /dev/null; then
    echo "Installing nmap..."
    sudo apt update
    sudo apt install -y nmap
fi

# Check if g++ is installed
if ! command -v g++ &> /dev/null; then
    echo "Installing g++..."
    sudo apt install -y g++
fi

# Compile the tool
echo "Compiling webscan.cpp..."
g++ -o webscan webscan.cpp -pthread -std=c++11

if [ $? -eq 0 ]; then
    echo "Installation successful!"
    echo "Run: ./webscan example.com"
    chmod +x webscan
else
    echo "Compilation failed!"
    exit 1
fi
