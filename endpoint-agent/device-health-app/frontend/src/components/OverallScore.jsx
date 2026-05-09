import React, { useEffect, useState } from 'react';

function OverallScore({ score }) {
    const [animatedScore, setAnimatedScore] = useState(0);

    useEffect(() => {
        const duration = 1000;
        const startTime = Date.now();

        const animate = () => {
            const elapsed = Date.now() - startTime;
            const progress = Math.min(elapsed / duration, 1);
            const eased = 1 - Math.pow(1 - progress, 3);
            setAnimatedScore(Math.round(eased * score));

            if (progress < 1) {
                requestAnimationFrame(animate);
            }
        };

        requestAnimationFrame(animate);
    }, [score]);

    const radius = 54;
    const circumference = 2 * Math.PI * radius;
    const strokeDashoffset = circumference - (animatedScore / 100) * circumference;

    const getColor = (s) => {
        if (s >= 80) return '#22c55e';
        if (s >= 60) return '#eab308';
        if (s >= 40) return '#f97316';
        return '#ef4444';
    };

    const getLabel = (s) => {
        if (s >= 80) return 'Excellent';
        if (s >= 60) return 'Good';
        if (s >= 40) return 'Fair';
        return 'At Risk';
    };

    const color = getColor(animatedScore);

    return (
        <div className="overall-score">
            <svg className="score-ring" viewBox="0 0 140 140">
                <circle
                    cx="70" cy="70" r={radius}
                    fill="none"
                    stroke="rgba(255,255,255,0.04)"
                    strokeWidth="8"
                />
                <circle
                    cx="70" cy="70" r={radius}
                    fill="none"
                    stroke={color}
                    strokeWidth="8"
                    strokeLinecap="round"
                    strokeDasharray={circumference}
                    strokeDashoffset={strokeDashoffset}
                    style={{
                        transform: 'rotate(-90deg)',
                        transformOrigin: '50% 50%',
                        transition: 'stroke 0.4s ease'
                    }}
                />
            </svg>
            <div className="score-content">
                <span className="score-value" style={{ color }}>{animatedScore}</span>
                <span className="score-label">{getLabel(score)}</span>
                <span className="score-sublabel">Health Score</span>
            </div>
        </div>
    );
}

export default OverallScore;
