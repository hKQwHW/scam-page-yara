rule NflPiracyScam
{
    // https://urlscan.io/result/2c38bfa4-b13f-45b9-9067-c88f181b4930/#summary
    strings:
        $a = "live NFL from the UK, Europe, the US and across the world. We're on air 24/7 bringing you NFL every night of the week. NFL live stream, Live Broadcast - NFL live stream | streaming NFL. To watch NFL online in best quality as well performance we advice you to use google chrome/Safari as browser. You should as well disable Adblock or any adblocker, those are blocking needed resources to start most of the streams. NFL online broadcast. We advice you to refresh page to check if new feeds are added for any questions use the chat box or contact us via Facebook. NFL online video and links from international TV Channels - we do our best to provide you with multiples language feeds. Live Score and Results. Where can I watch NFL online - Here free and legit ! :"
    
    condition:
        $a
}
