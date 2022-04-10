rule PayPalSpamMethods
{
    // Code from a PayPal phishing page created by (or at least stolen by) a Telegram group about "spam methods" and other things
    strings:
        $a = /\<button.*\>Log In<\/button>/
        $b = "<title>Log in to your &#x50;&#x61;&#x79;&#x50;&#x61;&#x6C; Account</title>"
    
    condition:
        $a and $b
}
