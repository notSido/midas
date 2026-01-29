#!/bin/bash
# Fix Unicorn API compatibility

echo "Fixing Unicorn API compatibility..."

# Fix: Permission -> Prot
find src -name "*.rs" -type f | while read file; do
    sed -i.bak 's/unicorn_engine::unicorn_const::Permission/unicorn_engine::unicorn_const::Prot/g' "$file"
    sed -i.bak 's/Permission::/Prot::/g' "$file"
    sed -i.bak "s/Unicorn<'static, ()>/Unicorn<()>/g" "$file"
    sed -i.bak "s/perms: Permission/perms: Prot/g" "$file"
    rm -f "${file}.bak"
done

echo "Done! Files fixed."
