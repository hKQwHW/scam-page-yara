rule BestBillingScope
{
    strings:
        $scam_text = "am so glad to know you're gonna help out! you are one in a million do you know i didn't rest a wink? i was just turning and rolling on my bed thinking how i was gonna come up with such an amount so as to be home will you be coming to pick me up at the airport and would be staying at your surely refunding isnt a problem"

    condition:
        $scam_text
}
