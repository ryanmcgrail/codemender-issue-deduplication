enum CweFamilyType {
    CodeInjection,
    CommandInjection,
    CrossSiteScripting,
    Deserialization,
    HardcodedSecret,
    JwtSignatureBypass,
    PathTraversal,
    ServerSideRequestForgery,
    SessionExpiration,
    SqlInjection,
    WeakCrypto,
    XmlExternalEntity,
}

const CWE_FAMILIES: ReadonlyMap<CweFamilyType, number[]> = new Map<CweFamilyType, number[]>([
    [CweFamilyType.CodeInjection, [94, 95, 96]],
    [CweFamilyType.CommandInjection, [77, 78, 88]],
    [CweFamilyType.CrossSiteScripting, [79, 80, 83]],
    [CweFamilyType.Deserialization, [502]],
    [CweFamilyType.HardcodedSecret, [259, 798]],
    [CweFamilyType.JwtSignatureBypass, [347]],
    [CweFamilyType.PathTraversal, [22, 23, 36, 73, 434]],
    [CweFamilyType.ServerSideRequestForgery, [918]],
    [CweFamilyType.SessionExpiration, [613]],
    [CweFamilyType.SqlInjection, [89, 564, 943]],
    [CweFamilyType.WeakCrypto, [327, 328]],
    [CweFamilyType.XmlExternalEntity, [611, 776]],
]);