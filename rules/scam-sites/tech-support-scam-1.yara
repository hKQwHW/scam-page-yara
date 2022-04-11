rule TechSupportScam1
{
    // https://urlscan.io/result/035cab42-6d85-43c3-8a17-cda1b0172fc5/dom/
    strings:
        $a = "Windows Firewall"
        $b = "PLEASE call us within the next"
        $c = "malfunction of your computer"
        $d = "Windows was blocked due to questionable activity."
    
    condition:
        $a and $b and $c and $d
}
