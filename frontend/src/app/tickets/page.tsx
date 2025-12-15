import { TicketList } from '@/components/tickets/ticketlist';
import { dummyTicketsTest } from './dummytickets/page';



 export default function TicketListPage() {
    return(
        <>
            <h2>Ticket List</h2>
            <TicketList tickets={dummyTicketsTest} />
        </>
    );
 }