rule DiscrdGift
{
    // Code from a phishing page created by (or at least stolen by) Telegram group Bank log shop
    strings:
        $a = "Open your discord mobile and then go to settings then scan qr code to claim, thanks for using discord!"
    
    condition:
        $a
}
