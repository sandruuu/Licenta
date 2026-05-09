import { useState, useEffect } from 'react';
import { EventsOn } from "../../wailsjs/runtime/runtime";
import { RespondToPush } from "../../wailsjs/go/main/App";

function PushApproval() {
    const [challenge, setChallenge] = useState(null);
    const [responding, setResponding] = useState(false);
    const [result, setResult] = useState(null);

    useEffect(() => {
        const unsubscribe = EventsOn("push:challenge", (ch) => {
            setChallenge(ch);
            setResult(null);
        });
        return () => unsubscribe();
    }, []);

    const respond = async (decision) => {
        if (!challenge) return;
        setResponding(true);
        try {
            const err = await RespondToPush(challenge.id, decision);
            if (err) {
                setResult({ ok: false, message: err });
            } else {
                setResult({
                    ok: true,
                    message: decision === 'approved' ? 'Approved' : 'Denied'
                });
                setTimeout(() => {
                    setChallenge(null);
                    setResult(null);
                }, 2000);
            }
        } catch (err) {
            setResult({ ok: false, message: String(err) });
        } finally {
            setResponding(false);
        }
    };

    if (!challenge) return null;

    return (
        <div className="push-overlay">
            <div className="push-dialog">
                <div className="push-icon">🔔</div>
                <h2 className="push-title">MFA Push Request</h2>
                <div className="push-details">
                    <p><strong>User:</strong> {challenge.username}</p>
                    <p><strong>From:</strong> {challenge.source_ip}</p>
                </div>

                {result ? (
                    <div className={`push-result ${result.ok ? 'success' : 'error'}`}>
                        {result.message}
                    </div>
                ) : (
                    <div className="push-actions">
                        <button
                            className="push-btn approve"
                            onClick={() => respond('approved')}
                            disabled={responding}
                        >
                            {responding ? '…' : '✓ Approve'}
                        </button>
                        <button
                            className="push-btn deny"
                            onClick={() => respond('denied')}
                            disabled={responding}
                        >
                            {responding ? '…' : '✗ Deny'}
                        </button>
                    </div>
                )}
            </div>
        </div>
    );
}

export default PushApproval;
