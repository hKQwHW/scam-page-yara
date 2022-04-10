rule DiscrdGift
{
    strings:
        $a = "Open your discord mobile and then go to settings then scan qr code to claim, thanks for using discord!"
    
    condition:
        $a
}
