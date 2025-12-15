import Link from "next/link";
import styles from "./TicketList.module.css";

interface Ticket {
    id: number;
    title: string;
    status: string;
    author: string;
}

interface TicketListProps {
    tickets: Ticket[];
}

export function TicketList({ tickets }: TicketListProps) {
    return (
        <table className={styles.table}>
            <thead>
                <tr className={styles.headerRow}>
                    <th className={styles.header}>ID</th>
                    <th className={styles.header}>Title</th>
                    <th className={styles.header}>Status</th>
                    <th className={styles.header}>Author</th>
                </tr>
            </thead>
            <tbody>
                {tickets.map((ticket) => (
                    <tr key={ticket.id} 
                        className={styles.row}>
                        <td className={styles.cell}>{ticket.id}</td>
                        <td className={styles.cell}>
                            <Link
                                href={`/tickets/details/${ticket.id}`}
                                className={styles.link}
                            >
                                {ticket.title}
                            </Link>
                        </td>
                        <td className={styles.cell}>{ticket.status}</td>
                        <td className={styles.cell}>{ticket.author}</td>
                    </tr>
                ))}
            </tbody>
        </table>
    );
}