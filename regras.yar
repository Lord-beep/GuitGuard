
rule GitGuard_Test_Marker
{
    meta:
        description = "Regra de demonstração para testar a integração YARA"

    strings:
        $marker = "GITGUARD_YARA_TEST_MARKER_12345"

    condition:
        $marker
}
