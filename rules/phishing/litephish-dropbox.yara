rule NflPiracyScam
{
    // https://github.com/DarkSecsDevelopers/LitePhish/blob/main/websites/dropbox.html
    strings:
        $a = "<form action=.././modules/post.php method=POST>"
        $b = "<input type=email name=username placeholder=Email><br><br>"
        $c = "<img src=images/dropbox2.PNG style=float:right;margin-right:20px;margin-top:10px>"
        $d = "<center><img src=images/dropbox3.png width=46px height=46px>&nbsp&nbsp<img src=images/dropbox4.svg width=120px height=34px></center>"
    
    condition:
        all of them
}
