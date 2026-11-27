package cn.geodata.sso.cas.attr;

/**
 * Internal attribute keys carried on the authenticated principal.
 *
 * <p>Kept separate from the outward element names on purpose: the outward names belong to
 * {@code cas_attribute_mapping} (changeable without code), while these keys are the internal
 * contract between the user store and the assembler.
 */
public final class CasPrincipalAttributes {

    public static final String USERNAME = "legacy.username";
    public static final String USER_ID = "legacy.userid";
    public static final String REAL_NAME = "legacy.realName";
    public static final String WORK_FOR = "legacy.workFor";
    public static final String EMAIL = "legacy.email";
    public static final String MOBILE = "legacy.mobile";
    public static final String CREATED_FROM = "legacy.createdFrom";
    public static final String IS_ENABLED = "legacy.isEnabled";
    public static final String ROLE_ID = "legacy.roleId";
    public static final String ROLE_NAME = "legacy.roleName";

    private CasPrincipalAttributes() {
    }
}
