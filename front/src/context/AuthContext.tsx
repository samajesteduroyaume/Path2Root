import React, { createContext, useContext, useState, useEffect } from 'react';
import axios from 'axios';

interface User {
    username: string;
    role: string;
    token: string;
}

interface AuthContextType {
    user: User | null;
    login: (token: string, role: string, username: string) => void;
    logout: () => void;
    isAuthenticated: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
    const [user, setUser] = useState<User | null>(null);

    useEffect(() => {
        const savedUser = localStorage.getItem('path2root_user');
        if (savedUser) {
            setUser(JSON.parse(savedUser));
        }
    }, []);

    const login = (token: string, role: string, username: string) => {
        const newUser = { token, role, username };
        setUser(newUser);
        localStorage.setItem('path2root_user', JSON.stringify(newUser));
        axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
    };

    const logout = () => {
        setUser(null);
        localStorage.removeItem('path2root_user');
        delete axios.defaults.headers.common['Authorization'];
    };

    return (
        <AuthContext.Provider value={{ user, login, logout, isAuthenticated: !!user }}>
            {children}
        </AuthContext.Provider>
    );
};

export const useAuth = () => {
    const context = useContext(AuthContext);
    if (context === undefined) {
        throw new Error('useAuth must be used within an AuthProvider');
    }
    return context;
};
