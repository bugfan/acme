# to fix mac vscode no code pursuit
file="./go.mod"
if [ -f "$file" ]; then
    mv go.mod go.mod1
    mv go.sum go.sum1
else
    mv go.mod1 go.mod
    mv go.sum1 go.sum
fi
