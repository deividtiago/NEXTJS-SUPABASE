// src/app/tickets/details/[id]/page.tsx
import { TicketComments } from '@/components/tickets/details[id]/ticketcomments';
import { dummyTicketsTest } from '../../dummytickets/page';
import styles from './TicketDetails.module.css';

interface TicketDetailsPageProps {
    params: Promise<{
        id: string;
    }>;
}

export default async function TicketDetailsPage({ params }: TicketDetailsPageProps) {
    const { id } = await params;
    const ticketId = parseInt(id);
    const ticket = dummyTicketsTest.find(t => t.id === ticketId);

    if (!ticket) {
        return (
            <div>
                <h2>Ticket Not Found</h2>
                <p>The ticket with ID {id} does not exist.</p>
            </div>
        );
    }

    return (
        <article className={styles.ticketDetails}>
            <header>
                <h2>
                    #{ticket.id} - <span className={styles.ticketStatusGreen}>{ticket.status}</span>
                </h2>
                <small className={styles.authorAndDate}>
                    Created by <strong>{ticket.author}</strong> at {ticket.createdAt}
                </small>
            </header>
            
            <h3>{ticket.title}</h3>
            
            <section>
                <p>{ticket.description}</p>
            </section>

            <TicketComments />
        </article>
    );
}