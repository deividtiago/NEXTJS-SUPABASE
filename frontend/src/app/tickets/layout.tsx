import Nav from '@/components/tickets/nav';
import TenantName from "@/components/tickets/tenantname";

export default function TicketsLayout(pageProps: any) {
    return(
        <>
            <section style={{ borderBottom: "1px solid gray"}}>
                {/* tenant name component goes here */}
                <TenantName tenantName="Projeto" />
                {/* navigation component goes here */}
                <Nav />
            </section>

            <section>{pageProps.children}</section>
        </>
    );
}