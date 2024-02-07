import "math"

private rule tree0
{
    strings:
		$s0 = "2e5ba9a36bdb0a6f6f3ea57601a6c606" fullword
		$s3 = "8285d8103b53d0216eab0d148f23b9aa" fullword
		$s4 = "1f8b8cd2c18a1f3466b06e907799c12e" fullword
		$s7 = "9f4848c2e5d47447576e9ffa90a4d44f" fullword

    condition:
((#s0 <= 1.0)
 and ( (filesize <= 372.5)
 or  (filesize > 372.5)
 and (  (#s3 <= 1.0)
 and (   (#s4 <= 1.0)
 and (    (filesize > 1491.0)
 and (     (#s7 <= 1.0)
 and (      (filesize <= 1908.0)
) or      (#s7 > 1.0)
)) or    (#s4 > 1.0)
) or   (#s3 > 1.0)
)) or (#s0 > 1.0)
)
}



private rule tree1
{
    strings:
		$s0 = "8285d8103b53d0216eab0d148f23b9aa" fullword
		$s1 = "9f4848c2e5d47447576e9ffa90a4d44f" fullword
		$s2 = "1f8b8cd2c18a1f3466b06e907799c12e" fullword
		$s3 = "ee4c4a4d8c733c2c0ca29ea25d4425f5" fullword
		$s4 = "2e5ba9a36bdb0a6f6f3ea57601a6c606" fullword

    condition:
((#s0 <= 1.0)
 and ( (#s1 <= 1.0)
 and (  (#s2 <= 1.0)
 and (   (#s3 <= 1.0)
 and (    (#s4 <= 1.0)
 and (     (filesize <= 372.5)
 and (      (filesize > 178.0)
) or      (filesize > 372.5)
 and (      (filesize > 1491.0)
 and (       (filesize <= 1908.0)
))) or     (#s4 > 1.0)
) or    (#s3 > 1.0)
) or   (#s2 > 1.0)
) or  (#s1 > 1.0)
) or (#s0 > 1.0)
)
}



private rule tree2
{
    strings:
		$s0 = "1f8b8cd2c18a1f3466b06e907799c12e" fullword
		$s5 = "2e5ba9a36bdb0a6f6f3ea57601a6c606" fullword
		$s8 = "8285d8103b53d0216eab0d148f23b9aa" fullword
		$s9 = "9f4848c2e5d47447576e9ffa90a4d44f" fullword

    condition:
((#s0 <= 1.0)
 and ( (filesize <= 435.5)
 and (  (filesize > 178.0)
) or  (filesize > 435.5)
 and (  (#s5 <= 1.0)
 and (   (filesize > 1493.0)
 and (    (#s8 <= 1.0)
 and (     (#s9 <= 1.0)
 and (      (filesize <= 1908.0)
) or      (#s9 > 1.0)
) or     (#s8 > 1.0)
)) or   (#s5 > 1.0)
)) or (#s0 > 1.0)
)
}



private rule tree3
{
    strings:


    condition:
((filesize <= 372.5)
 and ( (filesize > 178.0)
) or (filesize > 372.5)
 and ( (filesize > 1491.0)
 and (  (filesize <= 1908.0)
)))
}



private rule tree4
{
    strings:
		$s0 = "8285d8103b53d0216eab0d148f23b9aa" fullword
		$s1 = "9f4848c2e5d47447576e9ffa90a4d44f" fullword
		$s2 = "2e5ba9a36bdb0a6f6f3ea57601a6c606" fullword
		$s3 = "1f8b8cd2c18a1f3466b06e907799c12e" fullword
		$s4 = "ee4c4a4d8c733c2c0ca29ea25d4425f5" fullword

    condition:
((#s0 <= 1.0)
 and ( (#s1 <= 1.0)
 and (  (#s2 <= 1.0)
 and (   (#s3 <= 1.0)
 and (    (#s4 <= 1.0)
 and (     (filesize <= 373.0)
 and (      (filesize <= 178.0)
 or       (filesize > 178.0)
) or      (filesize > 373.0)
 and (      (filesize > 1474.0)
 and (       (filesize <= 1915.0)
))) or     (#s4 > 1.0)
) or    (#s3 > 1.0)
) or   (#s2 > 1.0)
) or  (#s1 > 1.0)
) or (#s0 > 1.0)
)
}



private rule tree5
{
    strings:
		$s0 = "1f8b8cd2c18a1f3466b06e907799c12e" fullword
		$s1 = "2e5ba9a36bdb0a6f6f3ea57601a6c606" fullword
		$s2 = "8285d8103b53d0216eab0d148f23b9aa" fullword
		$s7 = "9f4848c2e5d47447576e9ffa90a4d44f" fullword

    condition:
((#s0 <= 1.0)
 and ( (#s1 <= 1.0)
 and (  (#s2 <= 1.0)
 and (   (filesize <= 372.5)
 and (    (filesize <= 178.0)
 or     (filesize > 178.0)
) or    (filesize > 372.5)
 and (    (#s7 <= 1.0)
 and (     (filesize > 1492.5)
 and (      (filesize <= 1908.0)
)) or     (#s7 > 1.0)
)) or   (#s2 > 1.0)
) or  (#s1 > 1.0)
) or (#s0 > 1.0)
)
}



private rule tree6
{
    strings:
		$s0 = "1f8b8cd2c18a1f3466b06e907799c12e" fullword
		$s1 = "9f4848c2e5d47447576e9ffa90a4d44f" fullword
		$s4 = "2e5ba9a36bdb0a6f6f3ea57601a6c606" fullword
		$s5 = "ee4c4a4d8c733c2c0ca29ea25d4425f5" fullword
		$s6 = "8285d8103b53d0216eab0d148f23b9aa" fullword

    condition:
((#s0 <= 1.0)
 and ( (#s1 <= 1.0)
 and (  (filesize <= 371.5)
 or   (filesize > 371.5)
 and (   (#s4 <= 1.0)
 and (    (#s5 <= 1.0)
 and (     (#s6 <= 1.0)
 and (      (filesize > 1475.5)
 and (       (filesize <= 1908.0)
)) or      (#s6 > 1.0)
) or     (#s5 > 1.0)
) or    (#s4 > 1.0)
)) or  (#s1 > 1.0)
) or (#s0 > 1.0)
)
}



private rule tree7
{
    strings:
		$s0 = "ee4c4a4d8c733c2c0ca29ea25d4425f5" fullword
		$s5 = "8285d8103b53d0216eab0d148f23b9aa" fullword
		$s6 = "2e5ba9a36bdb0a6f6f3ea57601a6c606" fullword

    condition:
((#s0 <= 1.0)
 and ( (filesize <= 371.5)
 or  (filesize > 371.5)
 and (  (filesize > 1475.5)
 and (   (#s5 <= 1.0)
 and (    (#s6 <= 1.0)
 and (     (filesize <= 1908.0)
) or     (#s6 > 1.0)
) or    (#s5 > 1.0)
))) or (#s0 > 1.0)
)
}



private rule tree8
{
    strings:
		$s6 = "1f8b8cd2c18a1f3466b06e907799c12e" fullword

    condition:
((filesize <= 373.0)
 and ( (filesize > 178.0)
) or (filesize > 373.0)
 and ( (filesize > 1491.0)
 and (  (#s6 <= 1.0)
 and (   (filesize <= 1908.0)
) or   (#s6 > 1.0)
)))
}



private rule tree9
{
    strings:
		$s0 = "1f8b8cd2c18a1f3466b06e907799c12e" fullword
		$s5 = "9f4848c2e5d47447576e9ffa90a4d44f" fullword

    condition:
((#s0 <= 1.0)
 and ( (filesize <= 373.0)
 and (  (filesize <= 178.0)
 or   (filesize > 178.0)
) or  (filesize > 373.0)
 and (  (#s5 <= 1.0)
 and (   (filesize > 1467.0)
 and (    (filesize <= 1908.0)
)) or   (#s5 > 1.0)
)) or (#s0 > 1.0)
)
}



rule PII_detector
{
    condition:
	(tree0 and tree1 and tree2 and tree3 and tree4)
		 or (tree0 and tree1 and tree2 and tree3 and tree5)
		 or (tree0 and tree1 and tree2 and tree3 and tree6)
		 or (tree0 and tree1 and tree2 and tree3 and tree7)
		 or (tree0 and tree1 and tree2 and tree3 and tree8)
		 or (tree0 and tree1 and tree2 and tree3 and tree9)
		 or (tree0 and tree1 and tree2 and tree4 and tree5)
		 or (tree0 and tree1 and tree2 and tree4 and tree6)
		 or (tree0 and tree1 and tree2 and tree4 and tree7)
		 or (tree0 and tree1 and tree2 and tree4 and tree8)
		 or (tree0 and tree1 and tree2 and tree4 and tree9)
		 or (tree0 and tree1 and tree2 and tree5 and tree6)
		 or (tree0 and tree1 and tree2 and tree5 and tree7)
		 or (tree0 and tree1 and tree2 and tree5 and tree8)
		 or (tree0 and tree1 and tree2 and tree5 and tree9)
		 or (tree0 and tree1 and tree2 and tree6 and tree7)
		 or (tree0 and tree1 and tree2 and tree6 and tree8)
		 or (tree0 and tree1 and tree2 and tree6 and tree9)
		 or (tree0 and tree1 and tree2 and tree7 and tree8)
		 or (tree0 and tree1 and tree2 and tree7 and tree9)
		 or (tree0 and tree1 and tree2 and tree8 and tree9)
		 or (tree0 and tree1 and tree3 and tree4 and tree5)
		 or (tree0 and tree1 and tree3 and tree4 and tree6)
		 or (tree0 and tree1 and tree3 and tree4 and tree7)
		 or (tree0 and tree1 and tree3 and tree4 and tree8)
		 or (tree0 and tree1 and tree3 and tree4 and tree9)
		 or (tree0 and tree1 and tree3 and tree5 and tree6)
		 or (tree0 and tree1 and tree3 and tree5 and tree7)
		 or (tree0 and tree1 and tree3 and tree5 and tree8)
		 or (tree0 and tree1 and tree3 and tree5 and tree9)
		 or (tree0 and tree1 and tree3 and tree6 and tree7)
		 or (tree0 and tree1 and tree3 and tree6 and tree8)
		 or (tree0 and tree1 and tree3 and tree6 and tree9)
		 or (tree0 and tree1 and tree3 and tree7 and tree8)
		 or (tree0 and tree1 and tree3 and tree7 and tree9)
		 or (tree0 and tree1 and tree3 and tree8 and tree9)
		 or (tree0 and tree1 and tree4 and tree5 and tree6)
		 or (tree0 and tree1 and tree4 and tree5 and tree7)
		 or (tree0 and tree1 and tree4 and tree5 and tree8)
		 or (tree0 and tree1 and tree4 and tree5 and tree9)
		 or (tree0 and tree1 and tree4 and tree6 and tree7)
		 or (tree0 and tree1 and tree4 and tree6 and tree8)
		 or (tree0 and tree1 and tree4 and tree6 and tree9)
		 or (tree0 and tree1 and tree4 and tree7 and tree8)
		 or (tree0 and tree1 and tree4 and tree7 and tree9)
		 or (tree0 and tree1 and tree4 and tree8 and tree9)
		 or (tree0 and tree1 and tree5 and tree6 and tree7)
		 or (tree0 and tree1 and tree5 and tree6 and tree8)
		 or (tree0 and tree1 and tree5 and tree6 and tree9)
		 or (tree0 and tree1 and tree5 and tree7 and tree8)
		 or (tree0 and tree1 and tree5 and tree7 and tree9)
		 or (tree0 and tree1 and tree5 and tree8 and tree9)
		 or (tree0 and tree1 and tree6 and tree7 and tree8)
		 or (tree0 and tree1 and tree6 and tree7 and tree9)
		 or (tree0 and tree1 and tree6 and tree8 and tree9)
		 or (tree0 and tree1 and tree7 and tree8 and tree9)
		 or (tree0 and tree2 and tree3 and tree4 and tree5)
		 or (tree0 and tree2 and tree3 and tree4 and tree6)
		 or (tree0 and tree2 and tree3 and tree4 and tree7)
		 or (tree0 and tree2 and tree3 and tree4 and tree8)
		 or (tree0 and tree2 and tree3 and tree4 and tree9)
		 or (tree0 and tree2 and tree3 and tree5 and tree6)
		 or (tree0 and tree2 and tree3 and tree5 and tree7)
		 or (tree0 and tree2 and tree3 and tree5 and tree8)
		 or (tree0 and tree2 and tree3 and tree5 and tree9)
		 or (tree0 and tree2 and tree3 and tree6 and tree7)
		 or (tree0 and tree2 and tree3 and tree6 and tree8)
		 or (tree0 and tree2 and tree3 and tree6 and tree9)
		 or (tree0 and tree2 and tree3 and tree7 and tree8)
		 or (tree0 and tree2 and tree3 and tree7 and tree9)
		 or (tree0 and tree2 and tree3 and tree8 and tree9)
		 or (tree0 and tree2 and tree4 and tree5 and tree6)
		 or (tree0 and tree2 and tree4 and tree5 and tree7)
		 or (tree0 and tree2 and tree4 and tree5 and tree8)
		 or (tree0 and tree2 and tree4 and tree5 and tree9)
		 or (tree0 and tree2 and tree4 and tree6 and tree7)
		 or (tree0 and tree2 and tree4 and tree6 and tree8)
		 or (tree0 and tree2 and tree4 and tree6 and tree9)
		 or (tree0 and tree2 and tree4 and tree7 and tree8)
		 or (tree0 and tree2 and tree4 and tree7 and tree9)
		 or (tree0 and tree2 and tree4 and tree8 and tree9)
		 or (tree0 and tree2 and tree5 and tree6 and tree7)
		 or (tree0 and tree2 and tree5 and tree6 and tree8)
		 or (tree0 and tree2 and tree5 and tree6 and tree9)
		 or (tree0 and tree2 and tree5 and tree7 and tree8)
		 or (tree0 and tree2 and tree5 and tree7 and tree9)
		 or (tree0 and tree2 and tree5 and tree8 and tree9)
		 or (tree0 and tree2 and tree6 and tree7 and tree8)
		 or (tree0 and tree2 and tree6 and tree7 and tree9)
		 or (tree0 and tree2 and tree6 and tree8 and tree9)
		 or (tree0 and tree2 and tree7 and tree8 and tree9)
		 or (tree0 and tree3 and tree4 and tree5 and tree6)
		 or (tree0 and tree3 and tree4 and tree5 and tree7)
		 or (tree0 and tree3 and tree4 and tree5 and tree8)
		 or (tree0 and tree3 and tree4 and tree5 and tree9)
		 or (tree0 and tree3 and tree4 and tree6 and tree7)
		 or (tree0 and tree3 and tree4 and tree6 and tree8)
		 or (tree0 and tree3 and tree4 and tree6 and tree9)
		 or (tree0 and tree3 and tree4 and tree7 and tree8)
		 or (tree0 and tree3 and tree4 and tree7 and tree9)
		 or (tree0 and tree3 and tree4 and tree8 and tree9)
		 or (tree0 and tree3 and tree5 and tree6 and tree7)
		 or (tree0 and tree3 and tree5 and tree6 and tree8)
		 or (tree0 and tree3 and tree5 and tree6 and tree9)
		 or (tree0 and tree3 and tree5 and tree7 and tree8)
		 or (tree0 and tree3 and tree5 and tree7 and tree9)
		 or (tree0 and tree3 and tree5 and tree8 and tree9)
		 or (tree0 and tree3 and tree6 and tree7 and tree8)
		 or (tree0 and tree3 and tree6 and tree7 and tree9)
		 or (tree0 and tree3 and tree6 and tree8 and tree9)
		 or (tree0 and tree3 and tree7 and tree8 and tree9)
		 or (tree0 and tree4 and tree5 and tree6 and tree7)
		 or (tree0 and tree4 and tree5 and tree6 and tree8)
		 or (tree0 and tree4 and tree5 and tree6 and tree9)
		 or (tree0 and tree4 and tree5 and tree7 and tree8)
		 or (tree0 and tree4 and tree5 and tree7 and tree9)
		 or (tree0 and tree4 and tree5 and tree8 and tree9)
		 or (tree0 and tree4 and tree6 and tree7 and tree8)
		 or (tree0 and tree4 and tree6 and tree7 and tree9)
		 or (tree0 and tree4 and tree6 and tree8 and tree9)
		 or (tree0 and tree4 and tree7 and tree8 and tree9)
		 or (tree0 and tree5 and tree6 and tree7 and tree8)
		 or (tree0 and tree5 and tree6 and tree7 and tree9)
		 or (tree0 and tree5 and tree6 and tree8 and tree9)
		 or (tree0 and tree5 and tree7 and tree8 and tree9)
		 or (tree0 and tree6 and tree7 and tree8 and tree9)
		 or (tree1 and tree2 and tree3 and tree4 and tree5)
		 or (tree1 and tree2 and tree3 and tree4 and tree6)
		 or (tree1 and tree2 and tree3 and tree4 and tree7)
		 or (tree1 and tree2 and tree3 and tree4 and tree8)
		 or (tree1 and tree2 and tree3 and tree4 and tree9)
		 or (tree1 and tree2 and tree3 and tree5 and tree6)
		 or (tree1 and tree2 and tree3 and tree5 and tree7)
		 or (tree1 and tree2 and tree3 and tree5 and tree8)
		 or (tree1 and tree2 and tree3 and tree5 and tree9)
		 or (tree1 and tree2 and tree3 and tree6 and tree7)
		 or (tree1 and tree2 and tree3 and tree6 and tree8)
		 or (tree1 and tree2 and tree3 and tree6 and tree9)
		 or (tree1 and tree2 and tree3 and tree7 and tree8)
		 or (tree1 and tree2 and tree3 and tree7 and tree9)
		 or (tree1 and tree2 and tree3 and tree8 and tree9)
		 or (tree1 and tree2 and tree4 and tree5 and tree6)
		 or (tree1 and tree2 and tree4 and tree5 and tree7)
		 or (tree1 and tree2 and tree4 and tree5 and tree8)
		 or (tree1 and tree2 and tree4 and tree5 and tree9)
		 or (tree1 and tree2 and tree4 and tree6 and tree7)
		 or (tree1 and tree2 and tree4 and tree6 and tree8)
		 or (tree1 and tree2 and tree4 and tree6 and tree9)
		 or (tree1 and tree2 and tree4 and tree7 and tree8)
		 or (tree1 and tree2 and tree4 and tree7 and tree9)
		 or (tree1 and tree2 and tree4 and tree8 and tree9)
		 or (tree1 and tree2 and tree5 and tree6 and tree7)
		 or (tree1 and tree2 and tree5 and tree6 and tree8)
		 or (tree1 and tree2 and tree5 and tree6 and tree9)
		 or (tree1 and tree2 and tree5 and tree7 and tree8)
		 or (tree1 and tree2 and tree5 and tree7 and tree9)
		 or (tree1 and tree2 and tree5 and tree8 and tree9)
		 or (tree1 and tree2 and tree6 and tree7 and tree8)
		 or (tree1 and tree2 and tree6 and tree7 and tree9)
		 or (tree1 and tree2 and tree6 and tree8 and tree9)
		 or (tree1 and tree2 and tree7 and tree8 and tree9)
		 or (tree1 and tree3 and tree4 and tree5 and tree6)
		 or (tree1 and tree3 and tree4 and tree5 and tree7)
		 or (tree1 and tree3 and tree4 and tree5 and tree8)
		 or (tree1 and tree3 and tree4 and tree5 and tree9)
		 or (tree1 and tree3 and tree4 and tree6 and tree7)
		 or (tree1 and tree3 and tree4 and tree6 and tree8)
		 or (tree1 and tree3 and tree4 and tree6 and tree9)
		 or (tree1 and tree3 and tree4 and tree7 and tree8)
		 or (tree1 and tree3 and tree4 and tree7 and tree9)
		 or (tree1 and tree3 and tree4 and tree8 and tree9)
		 or (tree1 and tree3 and tree5 and tree6 and tree7)
		 or (tree1 and tree3 and tree5 and tree6 and tree8)
		 or (tree1 and tree3 and tree5 and tree6 and tree9)
		 or (tree1 and tree3 and tree5 and tree7 and tree8)
		 or (tree1 and tree3 and tree5 and tree7 and tree9)
		 or (tree1 and tree3 and tree5 and tree8 and tree9)
		 or (tree1 and tree3 and tree6 and tree7 and tree8)
		 or (tree1 and tree3 and tree6 and tree7 and tree9)
		 or (tree1 and tree3 and tree6 and tree8 and tree9)
		 or (tree1 and tree3 and tree7 and tree8 and tree9)
		 or (tree1 and tree4 and tree5 and tree6 and tree7)
		 or (tree1 and tree4 and tree5 and tree6 and tree8)
		 or (tree1 and tree4 and tree5 and tree6 and tree9)
		 or (tree1 and tree4 and tree5 and tree7 and tree8)
		 or (tree1 and tree4 and tree5 and tree7 and tree9)
		 or (tree1 and tree4 and tree5 and tree8 and tree9)
		 or (tree1 and tree4 and tree6 and tree7 and tree8)
		 or (tree1 and tree4 and tree6 and tree7 and tree9)
		 or (tree1 and tree4 and tree6 and tree8 and tree9)
		 or (tree1 and tree4 and tree7 and tree8 and tree9)
		 or (tree1 and tree5 and tree6 and tree7 and tree8)
		 or (tree1 and tree5 and tree6 and tree7 and tree9)
		 or (tree1 and tree5 and tree6 and tree8 and tree9)
		 or (tree1 and tree5 and tree7 and tree8 and tree9)
		 or (tree1 and tree6 and tree7 and tree8 and tree9)
		 or (tree2 and tree3 and tree4 and tree5 and tree6)
		 or (tree2 and tree3 and tree4 and tree5 and tree7)
		 or (tree2 and tree3 and tree4 and tree5 and tree8)
		 or (tree2 and tree3 and tree4 and tree5 and tree9)
		 or (tree2 and tree3 and tree4 and tree6 and tree7)
		 or (tree2 and tree3 and tree4 and tree6 and tree8)
		 or (tree2 and tree3 and tree4 and tree6 and tree9)
		 or (tree2 and tree3 and tree4 and tree7 and tree8)
		 or (tree2 and tree3 and tree4 and tree7 and tree9)
		 or (tree2 and tree3 and tree4 and tree8 and tree9)
		 or (tree2 and tree3 and tree5 and tree6 and tree7)
		 or (tree2 and tree3 and tree5 and tree6 and tree8)
		 or (tree2 and tree3 and tree5 and tree6 and tree9)
		 or (tree2 and tree3 and tree5 and tree7 and tree8)
		 or (tree2 and tree3 and tree5 and tree7 and tree9)
		 or (tree2 and tree3 and tree5 and tree8 and tree9)
		 or (tree2 and tree3 and tree6 and tree7 and tree8)
		 or (tree2 and tree3 and tree6 and tree7 and tree9)
		 or (tree2 and tree3 and tree6 and tree8 and tree9)
		 or (tree2 and tree3 and tree7 and tree8 and tree9)
		 or (tree2 and tree4 and tree5 and tree6 and tree7)
		 or (tree2 and tree4 and tree5 and tree6 and tree8)
		 or (tree2 and tree4 and tree5 and tree6 and tree9)
		 or (tree2 and tree4 and tree5 and tree7 and tree8)
		 or (tree2 and tree4 and tree5 and tree7 and tree9)
		 or (tree2 and tree4 and tree5 and tree8 and tree9)
		 or (tree2 and tree4 and tree6 and tree7 and tree8)
		 or (tree2 and tree4 and tree6 and tree7 and tree9)
		 or (tree2 and tree4 and tree6 and tree8 and tree9)
		 or (tree2 and tree4 and tree7 and tree8 and tree9)
		 or (tree2 and tree5 and tree6 and tree7 and tree8)
		 or (tree2 and tree5 and tree6 and tree7 and tree9)
		 or (tree2 and tree5 and tree6 and tree8 and tree9)
		 or (tree2 and tree5 and tree7 and tree8 and tree9)
		 or (tree2 and tree6 and tree7 and tree8 and tree9)
		 or (tree3 and tree4 and tree5 and tree6 and tree7)
		 or (tree3 and tree4 and tree5 and tree6 and tree8)
		 or (tree3 and tree4 and tree5 and tree6 and tree9)
		 or (tree3 and tree4 and tree5 and tree7 and tree8)
		 or (tree3 and tree4 and tree5 and tree7 and tree9)
		 or (tree3 and tree4 and tree5 and tree8 and tree9)
		 or (tree3 and tree4 and tree6 and tree7 and tree8)
		 or (tree3 and tree4 and tree6 and tree7 and tree9)
		 or (tree3 and tree4 and tree6 and tree8 and tree9)
		 or (tree3 and tree4 and tree7 and tree8 and tree9)
		 or (tree3 and tree5 and tree6 and tree7 and tree8)
		 or (tree3 and tree5 and tree6 and tree7 and tree9)
		 or (tree3 and tree5 and tree6 and tree8 and tree9)
		 or (tree3 and tree5 and tree7 and tree8 and tree9)
		 or (tree3 and tree6 and tree7 and tree8 and tree9)
		 or (tree4 and tree5 and tree6 and tree7 and tree8)
		 or (tree4 and tree5 and tree6 and tree7 and tree9)
		 or (tree4 and tree5 and tree6 and tree8 and tree9)
		 or (tree4 and tree5 and tree7 and tree8 and tree9)
		 or (tree4 and tree6 and tree7 and tree8 and tree9)
		 or (tree5 and tree6 and tree7 and tree8 and tree9)
}
    