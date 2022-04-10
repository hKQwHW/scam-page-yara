rule BtcScamInstructions
{
    strings:
        $scam_text = "Please forgive me for stressing you with my predicaments and I sorry to approach you through this media it is because it serves the fastest means of communication. I came across your E-mail from my personal search and I decided to contact you believing you will be honest to fulfill my final wish before I die."

    condition:
        $scam_text
}
