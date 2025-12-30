import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import { Login } from './Login';
import { AuthProvider } from '../context/AuthContext';

// Mock axios
vi.mock('axios', () => ({
    default: {
        post: vi.fn(),
        defaults: { headers: { common: {} } }
    }
}));

describe('Login Component', () => {
    it('renders login form', () => {
        render(
            <AuthProvider>
                <Login onToggle={() => { }} />
            </AuthProvider>
        );
        expect(screen.getByText(/Access Portal/i)).toBeInTheDocument();
        expect(screen.getByPlaceholderText(/ID-7728-OP/i)).toBeInTheDocument();
    });

    it('allows entering username and password', () => {
        render(
            <AuthProvider>
                <Login onToggle={() => { }} />
            </AuthProvider>
        );
        const usernameInput = screen.getByPlaceholderText(/ID-7728-OP/i) as HTMLInputElement;
        const passwordInput = screen.getByPlaceholderText(/••••••••/i) as HTMLInputElement;

        fireEvent.change(usernameInput, { target: { value: 'testuser' } });
        fireEvent.change(passwordInput, { target: { value: 'password123' } });

        expect(usernameInput.value).toBe('testuser');
        expect(passwordInput.value).toBe('password123');
    });
});
