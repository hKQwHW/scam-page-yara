rule CitiBankScampage
{
    // Code from a phishing page created by (or at least stolen by) Telegram group Bank log shop
    strings:
        $a = "<form name=\"partnerLoginForm\" action=\"process/log1.php\" method=\"post\">"
        $b = "citi"
    
    condition:
        $a and $b
}
