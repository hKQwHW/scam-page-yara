rule TechSupportScam1
{
    // Code from a PayPal phishing page created by (or at least stolen by) a Telegram group about "spam methods" and other things
    strings:
        $a = "Windows Firewall"
        $b = "PLEASE call us within the next"
        $c = "malfunction of your computer"
        $d = "Windows was blocked due to questionable activity."
    
    condition:
        $a and $b and $c and $d
}
