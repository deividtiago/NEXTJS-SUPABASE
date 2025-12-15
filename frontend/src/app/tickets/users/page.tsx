import { users } from "./mockUsers";
import styles from "./TicketUsers.module.css";

function IconCheck() {
    return (
        <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M3 8l3 3 7-7" />
        </svg>
    );
}

function IconUserOff() {
    return (
        <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M2 2l12 12M10.5 6.5a3 3 0 1 1-5 0M13 13a6 6 0 0 0-10 0" />
        </svg>
    );
}

export default function UserList() {
    return (
        <div className={styles.container}>
            <table className={styles.table}>
                <thead>
                    <tr>
                        <th className={styles.th}>Name</th>
                        <th className={styles.th}>Job</th>
                    </tr>
                </thead>
                <tbody>
                    {users.map((user) => (
                        <tr key={user.name} className={styles.tr}>
                            <td className={`${styles.td} ${!user.isAvailable ? styles.unavailable : ''}`}>
                                <span className={styles.nameWrapper}>
                                    {user.isAvailable ? <IconCheck /> : <IconUserOff />}
                                    {user.name}
                                </span>
                            </td>
                            <td className={styles.td}>{user.job}</td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
}