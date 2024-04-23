package org.gridsuite.gateway;

import org.assertj.core.api.InstanceOfAssertFactories;
import org.assertj.core.api.WithAssertions;
import org.gridsuite.gateway.endpoints.*;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.context.ApplicationContext;
import reactor.test.StepVerifier;

import java.util.Map;

@SpringBootTest
class GatewayApplicationTest implements WithAssertions {
    @Autowired
    private ApplicationContext applicationContext;

    @Autowired
    private RouteLocator myRoutes;

    @Test
    void testAllEndpointServersFound() {
        assertThat(applicationContext.getBeansOfType(EndPointServer.class)).as("found EndPointServer beans")
            .allSatisfy((name, srv) -> assertThat(name).isEqualTo(srv.getEndpointName()))
            .extracting(Map::values, InstanceOfAssertFactories.collection(EndPointServer.class)).as("EndPointServer beans")
            .doesNotHaveDuplicates()
            .extracting(EndPointServer::getClass).as("EndPointServer classes")
            .containsExactlyInAnyOrder(
                CaseImportServer.class,
                CaseServer.class,
                CgmesBoundaryServer.class,
                CgmesGlServer.class,
                ConfigNotificationServer.class,
                ConfigServer.class,
                ContingencyServer.class,
                DirectoryNotificationServer.class,
                DirectoryServer.class,
                DynamicMappingServer.class,
                DynamicSimulationServer.class,
                ExploreServer.class,
                FilterServer.class,
                GeoDataServer.class,
                LoadFlowServer.class,
                MergeNotificationServer.class,
                MergeServer.class,
                NetworkConversionServer.class,
                NetworkModificationServer.class,
                OdreServer.class,
                ReportServer.class,
                SecurityAnalysisServer.class,
                SensitivityAnalysisServer.class,
                ShortCircuitServer.class,
                StudyNotificationServer.class,
                StudyServer.class,
                UserAdminServer.class,
                VoltageInitServer.class
        );
    }

    @Test
    void testRoutesInitialized() {
        StepVerifier.create(myRoutes.getRoutes())
                    .as("routes found")
                    .expectNextCount(28)
                    .verifyComplete();
    }
}
