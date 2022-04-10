rule BtcScamInstructions
{
    strings:
        $scam_text = "so when you get there baby First is click on buy bitcoins it will require verification by phone number so input your phone number a verification code will be sent to you instantly which you will again input the code into the machine might require your fingerprint or maybe not then it will tell you to select the coin you want to buy just click on bitcoin again then it will say do you want to scan wallet QR code or enter the address by typing"

    condition:
        $scam_text
}
