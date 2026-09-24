"""
Authentication and Role-Based Access Control (RBAC) Module.
Handles session state, user login/logout, password hashing, and user management UI.
"""

import streamlit as st
from typing import Optional, Dict, Any
from modules.database import db

def init_session_state() -> None:
    """Initializes authentication variables in Streamlit session state."""
    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False
    if "user" not in st.session_state:
        st.session_state.user = None
    if "role" not in st.session_state:
        st.session_state.role = None
    if "username" not in st.session_state:
        st.session_state.username = None

def get_current_user() -> Optional[Dict[str, Any]]:
    """Returns currently authenticated user dict or None."""
    return st.session_state.get("user")

def get_current_role() -> Optional[str]:
    """Returns role string ('Admin', 'Security Analyst', 'Viewer') or None."""
    return st.session_state.get("role")

def is_admin() -> bool:
    """Checks if the logged-in user has Admin privileges."""
    return st.session_state.get("role") == "Admin"

def is_analyst() -> bool:
    """Checks if the logged-in user is at least a Security Analyst."""
    return st.session_state.get("role") in ["Admin", "Security Analyst"]

def login_user(username: str, role: str, user_dict: Dict[str, Any]) -> None:
    """Sets session state upon successful authentication."""
    st.session_state.authenticated = True
    st.session_state.user = user_dict
    st.session_state.role = role
    st.session_state.username = username
    db.log_audit(username, "USER_LOGIN", f"User {username} ({role}) logged into SOC Dashboard.")

def logout_user() -> None:
    """Logs out user and clears session state."""
    username = st.session_state.get("username", "Unknown")
    db.log_audit(username, "USER_LOGOUT", f"User {username} logged out.")
    st.session_state.authenticated = False
    st.session_state.user = None
    st.session_state.role = None
    st.session_state.username = None
    st.rerun()

def render_login_form() -> None:
    """Renders the cyber-themed login form."""
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown("""
        <div style="text-align: center; margin-bottom: 24px;">
            <div style="font-size: 40px; margin-bottom: 8px;">🛡️</div>
            <h2 style="color: #00F5FF; font-weight: 800; margin: 0; letter-spacing: -0.5px;">CYBER SENTINEL SOC</h2>
            <p style="color: #94A3B8; font-size: 13px; margin-top: 4px;">AI-Powered Autonomous Threat Intelligence & Telemetry Analysis</p>
        </div>
        """, unsafe_allow_html=True)

        with st.container():
            # 1-Click Quick Access
            st.markdown("<div style='text-align: center; margin-bottom: 10px; font-size: 12px; font-weight: 600; color: #00F5FF;'>⚡ INSTANT 1-CLICK DEMO ACCESS</div>", unsafe_allow_html=True)
            q1, q2, q3 = st.columns(3)
            with q1:
                if st.button("👑 Admin", use_container_width=True, key="quick_admin", help="Instant login as Administrator"):
                    user = db.authenticate_user("admin", "Admin@12345")
                    if user:
                        login_user(user['username'], user['role'], user)
                        st.rerun()
            with q2:
                if st.button("🛡️ Analyst", use_container_width=True, key="quick_analyst", help="Instant login as Security Analyst"):
                    user = db.authenticate_user("analyst", "Analyst@12345")
                    if user:
                        login_user(user['username'], user['role'], user)
                        st.rerun()
            with q3:
                if st.button("👁️ Viewer", use_container_width=True, key="quick_viewer", help="Instant login as Viewer"):
                    user = db.authenticate_user("viewer", "Viewer@12345")
                    if user:
                        login_user(user['username'], user['role'], user)
                        st.rerun()

            st.markdown("<div style='text-align: center; margin: 8px 0 14px 0; color: #64748B; font-size: 11px;'>— OR SIGN IN MANUALLY —</div>", unsafe_allow_html=True)

            st.markdown("""
            <div style="background: rgba(17, 24, 39, 0.85); border: 1px solid rgba(0, 245, 255, 0.3); border-radius: 12px; padding: 24px; box-shadow: 0 8px 32px rgba(0, 245, 255, 0.1);">
            """, unsafe_allow_html=True)
            
            with st.form(key="login_form"):
                st.markdown("<h4 style='color: #F8FAFC; margin-top: 0;'>Analyst Authentication</h4>", unsafe_allow_html=True)
                username = st.text_input("Username / Call-Sign", placeholder="e.g. admin, analyst, viewer")
                password = st.text_input("Security Passphrase", type="password", placeholder="e.g. admin, viewer, or Admin@12345")
                
                submitted = st.form_submit_button("Authenticate Access", use_container_width=True)
                if submitted:
                    if not username or not password:
                        st.error("Please provide both username and passphrase.")
                    else:
                        user = db.authenticate_user(username.strip(), password.strip())
                        if user:
                            login_user(user['username'], user['role'], user)
                            st.success(f"Access Granted: Welcome {user.get('full_name') or user['username']} [{user['role']}]")
                            st.rerun()
                        else:
                            st.error("Access Denied: Invalid credentials.")
                            db.log_audit(username, "FAILED_LOGIN", "Authentication failure detected.")
            
            st.markdown("""
            </div>
            """, unsafe_allow_html=True)

        # Quick credentials info card for reviewers
        st.markdown("""
        <div style="margin-top: 20px; background: rgba(15, 23, 42, 0.5); border: 1px solid rgba(56, 189, 248, 0.2); border-radius: 8px; padding: 12px 16px; font-size: 12px; color: #94A3B8;">
            <span style="color: #00F5FF; font-weight: 700;">Accepted Credentials:</span><br>
            • <b>Admin:</b> <code>admin</code> / <code>admin</code> (or <code>Admin@12345</code>)<br>
            • <b>Security Analyst:</b> <code>analyst</code> / <code>analyst</code> (or <code>Analyst@12345</code>)<br>
            • <b>Viewer:</b> <code>viewer</code> / <code>viewer</code> (or <code>Viewer@12345</code>)
        </div>
        """, unsafe_allow_html=True)

def render_user_management() -> None:
    """Renders user management panel for Administrators."""
    st.subheader("👥 User Management & Role-Based Access Control")
    st.caption("Provision SOC team credentials and adjust access tiers.")

    if not is_admin():
        st.warning("⚠️ Restricted Area: Only SOC Administrators may manage user accounts.")
        return

    tab1, tab2 = st.tabs(["Active Personnel", "Provision New User"])

    with tab1:
        users = db.list_users()
        if users:
            for u in users:
                c1, c2, c3, c4, c5 = st.columns([2, 2, 2, 2, 1])
                c1.write(f"**{u['username']}**")
                c2.write(f"`{u['role']}`")
                c3.write(u['full_name'] or "—")
                c4.caption(f"Created: {u['created_at'][:10] if u['created_at'] else '—'}")
                if c5.button("🗑️", key=f"del_user_{u['id']}", help="Delete user"):
                    if db.delete_user(u['id']):
                        st.success(f"User {u['username']} removed.")
                        db.log_audit(st.session_state.username, "DELETE_USER", f"Removed user {u['username']}")
                        st.rerun()
                    else:
                        st.error("Cannot delete the only remaining Administrator.")
        else:
            st.info("No users registered.")

    with tab2:
        with st.form("create_user_form"):
            new_user = st.text_input("Username", placeholder="e.g. jdoe_soc")
            new_pass = st.text_input("Password", type="password", placeholder="••••••••••••")
            new_role = st.selectbox("Role Assignment", ["Security Analyst", "Viewer", "Admin"])
            new_fullname = st.text_input("Full Name", placeholder="e.g. Jane Doe")
            new_email = st.text_input("Corporate Email", placeholder="e.g. jdoe@soc.defense.corp")

            if st.form_submit_button("Provision User Account", use_container_width=True):
                if not new_user or not new_pass:
                    st.error("Username and password are required.")
                elif len(new_pass) < 6:
                    st.error("Password must be at least 6 characters long.")
                else:
                    if db.create_user(new_user.strip(), new_pass, new_role, new_fullname.strip(), new_email.strip()):
                        st.success(f"User account '{new_user}' created successfully.")
                        db.log_audit(st.session_state.username, "CREATE_USER", f"Created account {new_user} with role {new_role}")
                        st.rerun()
                    else:
                        st.error(f"Username '{new_user}' already exists.")
