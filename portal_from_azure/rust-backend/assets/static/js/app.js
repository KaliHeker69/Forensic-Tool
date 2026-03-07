/**
 * Resource Portal - Client-side JavaScript
 * Handles inactivity timeout, auto-logout, and UI interactions
 */

// ==================== Inactivity Timer ====================
let inactivityTimer;
let warningTimer;
let countdownInterval;
let timeRemaining;

const ACTIVITY_EVENTS = ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart', 'click'];
const WARNING_BEFORE_LOGOUT = 60 * 1000; // Show warning 60 seconds before logout

/**
 * Initialize the inactivity timer
 * @param {number} timeoutMs - Timeout in milliseconds
 */
function initInactivityTimer(timeoutMs) {
    // Only init on dashboard page
    if (!document.querySelector('.dashboard-page')) return;
    
    timeRemaining = timeoutMs;
    
    // Add event listeners for user activity
    ACTIVITY_EVENTS.forEach(event => {
        document.addEventListener(event, resetInactivityTimer, { passive: true });
    });
    
    startInactivityTimer(timeoutMs);
    updateTimerDisplay(timeoutMs);
}

/**
 * Start the inactivity timer
 * @param {number} timeoutMs - Timeout in milliseconds
 */
function startInactivityTimer(timeoutMs) {
    clearAllTimers();
    
    // Timer for showing the warning modal
    warningTimer = setTimeout(() => {
        showInactivityWarning();
    }, timeoutMs - WARNING_BEFORE_LOGOUT);
    
    // Timer for actual logout
    inactivityTimer = setTimeout(() => {
        performLogout();
    }, timeoutMs);
    
    // Update display every second
    let elapsed = 0;
    countdownInterval = setInterval(() => {
        elapsed += 1000;
        const remaining = timeoutMs - elapsed;
        updateTimerDisplay(remaining);
        
        if (remaining <= 0) {
            clearInterval(countdownInterval);
        }
    }, 1000);
}

/**
 * Reset the inactivity timer on user activity
 */
function resetInactivityTimer() {
    const modal = document.getElementById('inactivityModal');
    if (modal && !modal.hidden) {
        // If modal is shown, clicking anywhere except buttons should not reset
        return;
    }
    
    const timerElement = document.getElementById('sessionTimer');
    if (timerElement) {
        const timeoutMinutes = parseInt(timerElement.querySelector('.timer-text').textContent.split(':')[0]) || 15;
        startInactivityTimer(timeoutMinutes * 60 * 1000);
    }
}

/**
 * Clear all active timers
 */
function clearAllTimers() {
    clearTimeout(inactivityTimer);
    clearTimeout(warningTimer);
    clearInterval(countdownInterval);
}

/**
 * Update the session timer display
 * @param {number} remainingMs - Remaining time in milliseconds
 */
function updateTimerDisplay(remainingMs) {
    const timerElement = document.querySelector('#sessionTimer .timer-text');
    if (!timerElement) return;
    
    const minutes = Math.floor(remainingMs / 60000);
    const seconds = Math.floor((remainingMs % 60000) / 1000);
    timerElement.textContent = `${minutes}:${seconds.toString().padStart(2, '0')}`;
    
    // Change color when low
    if (remainingMs <= WARNING_BEFORE_LOGOUT) {
        timerElement.style.color = '#f59e0b';
    } else {
        timerElement.style.color = '';
    }
}

/**
 * Show the inactivity warning modal
 */
function showInactivityWarning() {
    const modal = document.getElementById('inactivityModal');
    if (!modal) return;
    
    modal.hidden = false;
    
    // Start countdown in modal
    let countdown = 60;
    const countdownElement = document.getElementById('countdownTimer');
    
    const countdownTimer = setInterval(() => {
        countdown--;
        if (countdownElement) {
            countdownElement.textContent = countdown;
        }
        
        if (countdown <= 0) {
            clearInterval(countdownTimer);
            performLogout();
        }
    }, 1000);
    
    // Store timer reference for cleanup
    modal.dataset.countdownTimer = countdownTimer;
}

/**
 * Perform logout action
 */
function performLogout() {
    window.location.href = '/auth/logout';
}

// ==================== UI Utilities ====================

/**
 * Show a toast notification
 * @param {string} message - Message to display
 * @param {string} type - Type: 'success', 'error', 'warning', 'info'
 */
function showToast(message, type = 'info') {
    // Remove existing toasts
    const existingToast = document.querySelector('.toast');
    if (existingToast) {
        existingToast.remove();
    }
    
    // Create toast element
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.innerHTML = `
        <span class="toast-icon">${getToastIcon(type)}</span>
        <span class="toast-message">${message}</span>
    `;
    
    // Add styles
    toast.style.cssText = `
        position: fixed;
        bottom: 20px;
        right: 20px;
        display: flex;
        align-items: center;
        gap: 10px;
        padding: 12px 20px;
        background: var(--bg-card);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 8px;
        box-shadow: var(--shadow-lg);
        z-index: 1001;
        animation: slideIn 0.3s ease;
    `;
    
    document.body.appendChild(toast);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        toast.style.animation = 'slideOut 0.3s ease forwards';
        setTimeout(() => toast.remove(), 300);
    }, 5000);
}

/**
 * Get icon for toast type
 * @param {string} type - Toast type
 * @returns {string} Icon emoji
 */
function getToastIcon(type) {
    const icons = {
        success: '<i class="fa-solid fa-check" aria-hidden="true"></i>',
        error: '<i class="fa-solid fa-xmark" aria-hidden="true"></i>',
        warning: '<i class="fa-solid fa-triangle-exclamation" aria-hidden="true"></i>',
        info: '<i class="fa-solid fa-info-circle" aria-hidden="true"></i>'
    };
    return icons[type] || icons.info;
}

// ==================== Keyboard Navigation ====================

document.addEventListener('DOMContentLoaded', () => {
    // Add keyboard navigation for resource cards
    const resourceCards = document.querySelectorAll('.resource-card:not(.coming-soon)');
    resourceCards.forEach(card => {
        card.setAttribute('tabindex', '0');
        card.addEventListener('keypress', (e) => {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                card.click();
            }
        });
    });
    
    // Handle escape key to close modals
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            const modal = document.getElementById('inactivityModal');
            if (modal && !modal.hidden) {
                // Reset timer instead of just closing
                modal.hidden = true;
                resetInactivityTimer();
            }
        }
    });
});

// ==================== Add CSS Animations ====================

const styleSheet = document.createElement('style');
styleSheet.textContent = `
    @keyframes slideIn {
        from {
            opacity: 0;
            transform: translateX(100px);
        }
        to {
            opacity: 1;
            transform: translateX(0);
        }
    }
    
    @keyframes slideOut {
        from {
            opacity: 1;
            transform: translateX(0);
        }
        to {
            opacity: 0;
            transform: translateX(100px);
        }
    }
`;
document.head.appendChild(styleSheet);
