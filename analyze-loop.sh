#!/bin/bash
# Analyze the hot loop addresses

SAMPLE="9c7702b4d702bbca82d20a7af16daba4809474fbf2cdca02cec5f3220a37111c.exe"

echo "Hot addresses in Themida loop:"
echo "0x14038d07e - executed 471,915 times"
echo "0x14038d089 - executed 471,915 times"  
echo "0x14038d080 - executed 471,915 times"
echo ""
echo "Converting to RVA (subtract image_base 0x140000000):"
echo "0x38d07e"
echo "0x38d089"
echo "0x38d080"
echo ""
echo "These are in the .boot section at RVA 0x38d000"
echo ""
echo "Only 199 unique addresses executed in 10M instructions!"
echo "This is a tight infinite loop waiting for something."
