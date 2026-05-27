// Authentication Functions

// Check if user is authenticated
function isAuthenticated() {
    return !!localStorage.getItem("token");
}


// Get current user
function getCurrentUser() {
    return JSON.parse(localStorage.getItem('user'));
}

// Redirect if not authenticated
function requireAuth() {
    if (!isAuthenticated()) {
        window.location.href = 'login.html';
        return false;
    }
    return true;
}

// Check role-based access
function hasRole(requiredRole) {
    const user = getCurrentUser();
    return user && user.role === requiredRole;
}

// Export functions
window.isAuthenticated = isAuthenticated;
window.getCurrentUser = getCurrentUser;
window.requireAuth = requireAuth;
window.hasRole = hasRole;