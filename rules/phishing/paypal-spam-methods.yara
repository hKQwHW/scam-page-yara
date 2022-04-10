rule PayPalSpamMethods
{
    // Code from a PayPal phishing page created by (or at least stolen by) a Telegram group about "spam methods" and other things
    strings:
        $a = "<button for=\"11152-xMARVELxDCxCOMIC18x-10835\" class=\"xXMARVELxXBut00N\" type=\"submit\" id=\"10967-x666G-10469\" name=\"10565-x968AG-11053\">Log In</button>"
    
    condition:
        $a
}
