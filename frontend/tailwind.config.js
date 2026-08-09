/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        // Deep, slightly blue-black console background rather than pure grey.
        void: '#05070d',
        surface: '#0b1120',
        elevated: '#111a2e',
        hairline: 'rgba(148, 178, 255, 0.12)',
        accent: {
          DEFAULT: '#22d3ee',
          soft: 'rgba(34, 211, 238, 0.14)',
        },
        severity: {
          critical: '#f43f5e',
          high: '#fb923c',
          medium: '#facc15',
          low: '#38bdf8',
          info: '#64748b',
        },
      },
      fontFamily: {
        sans: ['Inter', 'Segoe UI', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'SFMono-Regular', 'Consolas', 'monospace'],
      },
      boxShadow: {
        glass: '0 1px 0 0 rgba(255,255,255,0.06) inset, 0 18px 40px -24px rgba(0,0,0,0.9)',
        glow: '0 0 0 1px rgba(34,211,238,0.35), 0 0 28px -6px rgba(34,211,238,0.45)',
      },
      keyframes: {
        'pulse-ring': {
          '0%': { transform: 'scale(0.7)', opacity: '0.9' },
          '100%': { transform: 'scale(2.4)', opacity: '0' },
        },
        'slide-in': {
          from: { opacity: '0', transform: 'translateY(-6px)' },
          to: { opacity: '1', transform: 'translateY(0)' },
        },
        sweep: {
          '0%': { transform: 'translateX(-100%)' },
          '100%': { transform: 'translateX(300%)' },
        },
      },
      animation: {
        'pulse-ring': 'pulse-ring 2s ease-out infinite',
        'slide-in': 'slide-in 0.22s ease-out',
        sweep: 'sweep 2.4s ease-in-out infinite',
      },
    },
  },
  plugins: [],
}
