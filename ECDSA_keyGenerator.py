from cmath import inf
from secrets import randbelow

class Error(Exception):
    '''Usada para manejo de excepciones personalizadas''' 
    pass

class CurvaNoExiste(Error):
    '''Se levanta cuando la curva eliptica de Weirstrass en GF no existe'''
    def __init__(self, a: int,b: int,p: int) -> None:
        self.a,self.b,self.p= a,b,p
        self.mensaje = "La curva especificada no existe. Verifica que\
 (4a^3+27b^2) % p !=0"
        super().__init__(self.mensaje)


class curve:
    '''Clase usada para manejar las curvas como objetos'''
    def __init__(self,name: str,coefs: 'tuple[int,int]',p: int,G: 'tuple[int,int]',n: int,h: int) -> None:
        '''Construye el objeto de curva con sus parametros'''
        # Verificacion para confirmar que la curva existe, y se puede
        # definir un grupo 
        if (4*pow(coefs[0],3)+27*pow(coefs[1],2))%p !=0:
            # El nombre de la curva, solo para fines informativos
            self.name=name
            # Coeficientes (a,b) de la curva de campo finito. Estos son 0 o 1
            self.coefficients=(coefs[0],coefs[1])
            # El orden de la curva
            self.p= p
            # Generador de la curva
            self.G= (G[0],G[1])
            # Orden del generador
            self.n= n
            # Cofactor de la curva
            self.h= h
            # Usado para saber si se esta operando o no un cero
            self.zero= False
        else: 
            raise(CurvaNoExiste(coefs[0],coefs[1],p))
        

    def set_Q(self,P: 'tuple[int,int]') -> None:
        '''Inicializa el punto Q, usado para computaciones'''
        self.Q=P

    def point_doubling(self) -> None:
        '''Calcula la operacion de duplicar un punto'''
        # Verifica si el punto actual es un cero
        if self.zero==False:
            # Usado para verificar si la operacion 2p resulta en un cero
            try:
                lamb=((3*self.Q[0]**2+self.coefficients[0])*pow(2*self.Q[1], -1, self.p))%self.p
                x=(lamb**2-2*self.Q[0])%self.p
                y=(-self.Q[1]+lamb*(self.Q[0]-x))%self.p
                self.Q=(x,y)
            # Si 2p resulta en un cero, el inverso multiplicativo no existe
            # y en su lugar se define como 0
            except:
                self.Q=(self.Q[0],inf)
                self.zero=True

    def point_adition(self,P_1: 'tuple[int,int]',P_2: 'tuple[int,int]',ghost_eval: bool) -> None:
        '''Calcula la operacion de sumar 2 puntos P_1,P_2,P_1!=P_2'''
            # Lambda= (y2-y1)/(x2-x1) mod p
        try:
            lamb=((P_2[1]-P_1[1])*pow(P_2[0]-P_1[0],-1,self.p))%self.p
            # x= Lambda^2-x1-x2 mod p
            x=(lamb**2-P_1[0]-P_2[0])%self.p
            # y= -y1+Lambda(x1-x) mod p
            y=(-P_1[1]+lamb*(P_1[0]-x))%self.p
            # Usado para mitigar timing attacks, si se trata de una
            # evaluacion fantasma, el valor se computa pero no 
            # se asigna
        except:
            pass
        if not ghost_eval:
            #Verifica si el punto sumado resulta en un cero, 
            # si es asi, en lugar de asignar el punto, cambia
            # el booleano de cero a True
            if P_1[0]==P_2[0] and self.zero==False and P_1[1]==-P_2[1]%self.p:
                self.zero=True
                self.Q=(P_1[0],inf)
            # Si se esta sumando un punto a un cero, se ignoran las computaciones
            # y se asigna 0+P=P
            elif self.zero==True:
                self.Q=(P_2[0],P_2[1])
                self.zero=False
            # En cualquier otro caso el punto resulta en las computaciones anteriores
            else:
                self.Q=(x,y)
                self.zero=False





def secure_random(strenght: int) -> int:
    '''Funcion que genera un numero en el rango [0,n)
    de una manera criptograficamente segura'''
    return randbelow(strenght)

def public_key(curve: curve,privateKey:  int) -> curve:
    ''' Genera una clave publica a partir de una privada, y una curva.
    Devuelve una curva'''
    kbin=str(bin(privateKey))
    kbin=kbin[2:]
    m=len(kbin)
    if curve.zero==False:
        # Q=P
        curve.set_Q(curve.G)
        for i in range(1,m):
            # Se calcula Q=2P
            curve.point_doubling()
            if kbin[i]=='1':
                #Sucede justo despues de salir de un cero sumando 
                if curve.G==curve.Q:
                    curve.point_doubling()
                else:
                    curve.point_adition(curve.Q,curve.G,False)
            else:
                # Balanceo de operaciones para timing attacks
                curve.point_adition(curve.Q,curve.G,True)
    else:
        curve.point_adition(curve.Q,curve.G,False)
    return curve
    

